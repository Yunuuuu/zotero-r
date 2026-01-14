#' Zotero instance
#'
#' @param tags A boolean value indicating whether to retrieve the tags
#' associated with the request.
#' @param collection A specific collection in the library.
#' @param item A specific saved search in the library.
#' @param search A specific saved search in the library.
#' @param params A [`zotero_params()`] object defined the parameters used to
#' create the request.
#' @seealso
#' A full list of methods can be found here:
#' <http://www.zotero.org/support/dev/server_api>
#' @export
Zotero <- R6::R6Class(
    "Zotero",
    public = list(
        #' @description Initialize a new Zotero instance
        initialize = function() private$params <- zotero_params(),
        #' @description Set Zotero API key directly
        #' @param key A character string representing the Zotero API key. You
        #'   can create your private API key by visiting
        #'   <https://www.zotero.org/settings/keys>. If the `key` argument is
        #'   not provided, the function will attempt to use the value from the
        #'   environment variable `ZOTERO_API`.
        key_set = function(key) {
            if (missing(key)) {
                key <- Sys.getenv("ZOTERO_API", unset = NA, names = FALSE)
                if (is.na(key)) {
                    cli::cli_abort(paste(
                        "{.arg key} must be provdied",
                        "or you should set the environment variable {.envvar ZOTERO_API}"
                    ))
                }
                cli::cli_inform(c(
                    "v" = "Used Environment variable: {.envvar ZOTERO_API}"
                ))
            }
            assert_string(key, allow_empty = FALSE)
            private$reset()
            private$api_key <- key
            private$key_cached <- FALSE
            invisible(self)
        },

        #' @description OAuth authorization for the Zotero API
        #' @details This method must be used in an interactive session
        key_oauth = function() {
            if (!interactive()) {
                cli::cli_abort("OAuth authorization requires an interactive session.")
            }
            key_data <- zotero_oauth_token(
                private$oauth_request,
                private$oauth_authorize,
                private$oauth_access
            )
            private$reset()
            # we can use the `token secret` the same way we already used a
            # Zotero API key
            private$api_key <- .subset2(key_data, "oauth_token_secret")
            private$userid <- .subset2(key_data, "userid")
            private$username <- .subset2(key_data, "username")
            private$token <- .subset2(key_data, "oauth_token")
            private$key_cached <- FALSE
            cli::cli_inform(c(
                "v" = sprintf(
                    "OAuth authorization for user ID: {.field %s}",
                    private$userid
                )
            ))
            invisible(self)
        },

        #' @description Read the cached Zotero API key
        #' @param userid A string of user ID. If provided, the function will
        #'   attempt to find the cached key for this user. If not provided, the
        #'   function will attempt to use the last cached key. For your user ID,
        #'   visit <https://www.zotero.org/settings/keys>.
        key_read = function(userid = NULL) {
            assert_string(userid, allow_empty = FALSE, allow_null = TRUE)
            path <- credential_get(userid)
            cli::cli_inform(c(
                ">" = sprintf("Reading key from {.path %s}", path)
            ))
            key_data <- httr2::secret_read_rds(
                path,
                I(httr2_fun("unobfuscate")(.secret$obfuscate_key()))
            )
            private$reset()
            private$api_key <- .subset2(key_data, "api_key")
            private$userid <- .subset2(key_data, "userid")
            private$username <- .subset2(key_data, "username")
            private$token <- .subset2(key_data, "token")
            private$key_cached <- TRUE
            invisible(self)
        },

        #' @description Cache the Zotero API key
        key_cache = function() {
            private$ensure_key()
            # cache the credential key for future use
            cli::cli_inform(c(
                ">" = if (is.null(private$userid)) {
                    "Caching key"
                } else {
                    sprintf("Caching key for user ID: {.field %s}", private$userid)
                }
            ))
            # `acess` and `groups` can be changed after creation
            httr2::secret_write_rds(
                list(
                    api_key = private$api_key,
                    userid = private$userid,
                    username = private$username,
                    token = private$token
                    # access = private$access,
                    # groups = private$groups
                ),
                credential_path(private$userid),
                I(httr2_fun("unobfuscate")(.secret$obfuscate_key()))
            )
            private$key_cached <- TRUE

            # Save the user ID of the credential key for future reference
            credential_userids_file <- credential_userids_path()
            if (file.exists(credential_userids_file)) {
                credential_userids <- readRDS(credential_userids_file)
            } else {
                credential_userids <- NULL
            }
            credential_userids <- unique(c(private$userid, credential_userids))
            saveRDS(credential_userids, credential_userids_file)
            invisible(self)
        },

        #' @description Fill in missing information associated with the Zotero
        #' API key
        #' @details
        #' This method ensures that the Zotero API key is fully populated with
        #' the required user information (e.g., userid, username, and access
        #' level). If any of the key details are missing, it retrieves and
        #' completes the necessary information.
        key_complete_info = function() {
            private$ensure_key()
            if (!private$has_full_key_info()) private$complete_key_info()
            invisible(self)
        },

        #' @description Retrieve the Zotero user ID for the current API key
        key_userid = function() {
            private$ensure_key()
            if (is.null(private$userid)) private$complete_key_info()
            private$userid
        },

        #' @description Retrieve the Zotero user name for the current API key
        key_username = function() {
            private$ensure_key()
            if (is.null(private$username)) private$complete_key_info()
            private$username
        },

        #' @description Retrieve the access level for the current API key
        key_access = function() {
            private$ensure_key()
            if (is.null(private$access)) private$complete_key_info()
            private$access
        },

        #' @description Retrieve the list of groups the current API key has
        #' access to
        #' @details
        #' This method retrieves the set of groups the current API key has
        #' access to, including public groups the key owner belongs to, even if
        #' the key doesn't have explicit permissions for those groups. It is
        #' useful for identifying which groups a user or API key can interact
        #' with, including public groups and groups that the owner has
        #' membership in.
        key_groups = function() {
            if (is.null(private$groups)) {
                req <- private$request("users", self$key_userid(), "groups")
                resp <- private$req_perform(req)
                private$groups <- httr2::resp_body_json(resp)
            }
            private$groups
        },

        #' @description Revoke the current Zotero API key
        #' @details
        #' This method will also remove the cached file if the key is from the
        #' cached credential file.
        key_revoke = function() {
            # we need userid to remove the cached key
            private$ensure_key()
            req <- private$request("keys", private$api_key, method = "DELETE")
            req <- httr2::req_error(req, is_error = function(resp) FALSE)
            resp <- private$req_perform(req)
            status <- httr2::resp_status(resp)

            # Authentication errors (e.g., invalid API key or insufficient
            # privileges) will return a 403 Forbidden
            if (private$key_cached &&
                (!httr2::resp_is_error(resp) || status == 403L)) {
                userid <- self$key_userid()
                # remove the credential file
                credential_file <- credential_path(userid)
                if (file.exists(credential_file) &&
                    unlink(credential_file, force = TRUE)) {
                    cli::cli_warn(sprintf(
                        "Unable to remove file {.path %s}",
                        credential_file
                    ))
                }

                # remove the userid
                credential_userids_file <- credential_userids_path()
                if (file.exists(credential_userids_file)) {
                    credential_userids <- readRDS(credential_userids_file)
                    credential_userids <- setdiff(credential_userids, userid)
                    if (length(credential_userids)) {
                        saveRDS(credential_userids, credential_userids_file)
                    } else if (unlink(credential_userids_file, force = TRUE)) {
                        cli::cli_warn(sprintf(
                            "Unable to remove file {.path %s}",
                            credential_userids_file
                        ))
                    }
                }
                cli::cli_inform(c(
                    "v" = sprintf("Revoke key authorization for user ID: {.field %s}.", userid)
                ))
            } else {
                cli::cli_abort(c(
                    if (is.null(private$userid)) {
                        "Failed to revoke key authorization."
                    } else {
                        sprintf("Failed to revoke key authorization for user ID: {.field %s}.", private$userid)
                    },
                    i = sprintf("HTTP Status: %s", status)
                ))
            }
        },

        #' @description Determine or Set the Library
        #' @details
        #' This method allows you to specify the library from which to retrieve
        #' or manipulate data. The library ID is identified by a `user ID` or
        #' `group ID`. The library ID and its type (`user` or `group`) are
        #' essential for the request. By default, the `user ID` associated with
        #' the current API key is used.
        #'
        #' User IDs differ from usernames and can be found on the [API
        #' Keys](https://www.zotero.org/settings/keys) page or retrieved using
        #' the `$key_userid()` method. Group IDs are distinct from group names
        #' and can be obtained via the `$key_groups()` method.
        #'
        #' If no **library_id** is provided, the method will return the
        #' currently used library. If **library_id** is set to `NULL`, the
        #' library will be reset to the default.  Otherwise, if a **library_id**
        #' is provided, **library_type** will default to `"group"`, as it is
        #' uncommon for users to set a `user` type with a library ID that
        #' differs from the current API key's user ID.  If a **library_id** is
        #' provided with a non-default **library_type**, the **library_type**
        #' (`"user"` or `"group"`) must be specified.
        #' @param library_id A string representing either a `user ID` or
        #' `group ID` for the library.
        #' @param library_type A string of `"user"` or `"group"` representing
        #' the type for the library.
        #' @return A `zotero_library` object when **library_id** is missing,
        #' otherwise, returns the Zotero instance itself, allowing for method
        #' chaining.
        library = function(library_id, library_type) {
            if (missing(library_id)) {
                if (!missing(library_type)) {
                    cli::cli_warn("{.arg library_type} cannot be used when {.arg library_id} is missing")
                }
                # If no library_id is provided, use the userid by default
                if (is.null(private$zlibrary)) {
                    library_id <- self$key_userid()
                    library_type <- "user"
                    return(zotero_library(library_id, library_type))
                } else {
                    return(private$zlibrary)
                }
            }

            if (is.null(library_id)) {
                if (!missing(library_type)) {
                    cli::cli_warn("{.arg library_type} cannot be used when {.arg library_id} is {.code NULL}")
                }
                private$zlibrary <- NULL
            } else {
                if (missing(library_type)) {
                    # Default library_type to "group" if missing (as it's
                    # uncommon for users to use "user" type)
                    library_type <- "group"
                }
                private$zlibrary <- zotero_library(library_id, library_type)
            }
            invisible(self)
        },

        #' @description Determine or Set the global parameters
        #'
        #' @param ... Additional arguments passed on to [`zotero_params()`].
        #' @return A `zotero_params` object when `...` is empty, otherwise,
        #' returns the Zotero instance itself, allowing for method chaining.
        parameters = function(...) {
            if (...length() == 0L) return(private$params) # styler: off
            params <- zotero_params(...)
            private$params <- merge(private$params, params)
            invisible(self)
        },

        #' @description Perform the Zotero API Request
        #' @details
        #' This method constructs a request of the Zotero API and perform it. It
        #' allows you to specify the URL path components and optional query
        #' parameters, and includes support for prefixing library-specific paths
        #' (e.g., `/users/<userID>` or `/groups/<groupID>`) when interacting
        #' with data from specific libraries.
        #' @param ... Character strings representing the path components to
        #' append to the Zotero API base URL.
        #' @param library A [`zotero_library()`] object. If provided, the
        #' request URL will be prefixed with the relevant library path
        #' (`/users/<userID>` or `/groups/<groupID>`).
        #' @param query Optional named list of query parameters to be added to
        #' the request URL.
        #' @param method Custom HTTP method.
        #' @param path Optionally, path to save body of the response. This is
        #'   useful for large responses since it avoids storing the response in
        #'   memory.
        #' @param mock A mocking function. If supplied, this function is called
        #'   with the request. It should return either `NULL` (if it doesn't
        #'   want to handle the request) or a [response] (if it does). See
        #'   [with_mocked_responses()][httr2::with_mocked_responses]/`local_mocked_responses()`
        #'   for more details.
        #' @param verbosity How much information to print? This is a wrapper
        #'   around [req_verbose()][httr2::req_verbose] that uses an integer to
        #'   control verbosity:
        #'
        #'   * `0`: no output
        #'   * `1`: show headers
        #'   * `2`: show headers and bodies
        #'   * `3`: show headers, bodies, and curl status messages.
        #'
        #'   Use [with_verbosity()][httr2::with_verbosity] to control the
        #'   verbosity of requests that you can't affect directly.
        #' @returns
        #'   * If the HTTP request succeeds, and the status code is ok (e.g.
        #'     200), an HTTP [response][httr2::response].
        #'
        #'   * If the HTTP request succeeds, but the status code is an error
        #'     (e.g a 404), an error with class `c("httr2_http_404",
        #'     "httr2_http")`.  By default, all 400 and 500 status codes will be
        #'     treated as an error, but you can customise this with
        #'     [req_error()][httr2::req_error].
        #'
        #'   * If the HTTP request fails (e.g. the connection is dropped or the
        #'     server doesn't exist), an error with class `"httr2_failure"`.
        perform = function(..., library = NULL, query = NULL, method = NULL,
                           path = NULL, verbosity = NULL) {
            req <- private$request(...,
                query = query, method = method,
                library = library
            )
            private$req_perform(req, path = path, verbosity = verbosity)
        },

        #' @description Collections in the library
        collections = function(params = NULL) {
            req <- private$request(
                "collections",
                query = private$query(params),
                library = self$library()
            )
            private$req_perform(req)
        },

        #' @description Top-level collections in the library
        collections_top = function(params = NULL) {
            req <- private$request(
                "collections", "top",
                query = private$query(params),
                library = self$library()
            )
            private$req_perform(req)
        },

        #' @description A specific collection in the library
        collection = function(collection, params = NULL) {
            req <- private$req_collection(
                collection,
                query = private$query(params, pagination_params = FALSE)
            )
            private$req_perform(req)
        },

        #' @description Subcollections within a specific collection in the
        #' library
        collection_subgroups = function(collection, params = NULL) {
            req <- private$req_collection(
                collection, "collections",
                query = private$query(params)
            )
            private$req_perform(req)
        },

        #' @description Tags associated with a specific collection in the
        #' library
        collection_tags = function(collection, params = NULL) {
            req <- private$req_collection(
                collection, "tags",
                query = private$query(params, tag_search_params = TRUE)
            )
            private$req_perform(req)
        },

        #' @description Items within a specific collection in the library
        collection_items = function(collection, params = NULL) {
            req <- private$req_collection(
                collection, "items",
                query = private$query(params, item_search_params = TRUE)
            )
            private$req_perform(req)
        },

        #' @description Tags associated with the Items within a specific
        #' collection in the library
        collection_items_tags = function(collection, params = NULL) {
            req <- private$req_collection(
                collection, "items", "tags",
                query = private$query(
                    params,
                    item_search_params = TRUE,
                    tag_search_params = TRUE
                )
            )
            private$req_perform(req)
        },

        #' @description Top-level items within a specific collection in the
        #' library
        collection_items_top = function(collection, params = NULL) {
            req <- private$req_collection(
                collection, "items", "top",
                query = private$query(params, item_search_params = TRUE)
            )
            private$req_perform(req)
        },

        #' @description Tags associated with the top-level items within a
        #' specific collection in the library
        collection_items_top_tags = function(collection, params = NULL) {
            req <- private$req_collection(
                collection, "items", "top", "tags",
                query = private$query(
                    params,
                    item_search_params = TRUE,
                    tag_search_params = TRUE
                )
            )
            private$req_perform(req)
        },

        #' @description All items in the library, excluding trashed items
        items = function(params = NULL) {
            req <- private$request(
                "items",
                query = private$query(params, item_search_params = TRUE),
                library = self$library()
            )
            private$req_perform(req)
        },

        #' @description Tags associated all items in the library, excluding
        #' trashed items
        items_tags = function(params = NULL) {
            req <- private$request(
                "items", "tags",
                query = private$query(
                    params,
                    item_search_params = TRUE,
                    tag_search_params = TRUE
                ),
                library = self$library()
            )
            private$req_perform(req)
        },

        #' @description Top-level items in the library, excluding trashed items
        items_top = function(params = NULL) {
            req <- private$request(
                "items", "top",
                query = private$query(params, item_search_params = TRUE),
                library = self$library()
            )
            private$req_perform(req)
        },

        #' @description Tags associated with the top-level items in the library
        items_top_tags = function(params = NULL) {
            req <- private$request(
                "items", "top", "tags",
                query = private$query(
                    params,
                    item_search_params = TRUE,
                    tag_search_params = TRUE
                ),
                library = self$library()
            )
            private$req_perform(req)
        },

        #' @description Items in the trash
        items_trash = function(params = NULL) {
            req <- private$request(
                "items", "trash",
                query = private$query(
                    params,
                    include_trash_param = FALSE,
                    item_search_params = TRUE
                ),
                library = self$library()
            )
            private$req_perform(req)
        },

        #' @description Tags associated with the items in the trash
        items_trash_tags = function(params = NULL) {
            req <- private$request(
                "items", "trash", "tags",
                query = private$query(
                    params,
                    include_trash_param = FALSE,
                    item_search_params = TRUE,
                    tag_search_params = TRUE
                ),
                library = self$library()
            )
            private$req_perform(req)
        },

        #' @description A specific item in the library
        item = function(item, params = NULL) {
            req <- private$req_item(
                item,
                query = private$query(
                    params,
                    pagination_params = FALSE
                )
            )
            private$req_perform(req)
        },

        #' @description Tags associated with a specific item in the library
        item_tags = function(item, params = NULL) {
            req <- private$req_item(
                item, "tags",
                query = private$query(
                    params,
                    tag_search_params = TRUE
                )
            )
            private$req_perform(req)
        },

        #' @description Child items under a specific item
        item_children = function(item, params = NULL) {
            req <- private$req_item(
                item, "children",
                query = private$query(
                    params,
                    item_search_params = TRUE
                )
            )
            private$req_perform(req)
        },

        #' @description Items in My Publications
        publication_items = function(params = NULL) {
            req <- private$request(
                "publications", "items",
                query = private$query(
                    params,
                    item_search_params = TRUE
                ),
                library = self$library()
            )
            private$req_perform(req)
        },

        #' @description Tags associated with the items in My Publications
        publication_items_tags = function(params = NULL) {
            req <- private$request(
                "publications", "items", "tags",
                query = private$query(
                    params,
                    item_search_params = TRUE,
                    tag_search_params = TRUE
                ),
                library = self$library()
            )
            private$req_perform(req)
        },

        #' @description Get all saved searches in the library
        #' @details Only get the saved searches, not search results.
        saved_searches = function() {
            req <- private$request("searches", library = self$library())
            private$req_perform(req)
        },

        #' @description Get a specific saved search in the library
        #' @details Only get the saved searches, not search results.
        saved_search = function(search) {
            assert_string(search, allow_empty = FALSE)
            req <- private$request(
                "searches", search,
                library = self$library()
            )
            private$req_perform(req)
        },

        #' @description All tags in the library
        tags = function(params = NULL) {
            req <- private$request("tags",
                query = private$query(
                    params,
                    tag_search_params = TRUE
                ),
                library = self$library()
            )
            private$req_perform(req)
        },

        # Zotero Web API Item Type/Field Requests
        item_types = function() {
            req <- private$request("itemTypes", method = "GET")
            private$req_perform(req)
        },
        item_fields = function(item_type = NULL) {
            if (is.null(item_type)) {
                req <- private$request("itemFields", method = "GET")
            } else {
                req <- private$request("itemTypeFields",
                    query = list(itemType = item_type), method = "GET",
                )
            }
            private$req_perform(req)
        },
        creator_types = function(item_type) {
            req <- private$request("itemTypeCreatorTypes",
                query = list(itemType = item_type), method = "GET"
            )
            private$req_perform(req)
        },
        creator_fields = function(item_type = NULL) {
            req <- private$request("creatorFields",
                query = list(itemType = item_type), method = "GET"
            )
            private$req_perform(req)
        },
        new_item = function(item_type) {
            req <- private$request(
                "items", "new",
                query = list(itemType = item_type), method = "GET"
            )
            private$req_perform(req)
        },
    ),
    private = list(
        api = "https://api.zotero.org",
        oauth_request = "https://www.zotero.org/oauth/request",
        oauth_access = "https://www.zotero.org/oauth/access",
        oauth_authorize = "https://www.zotero.org/oauth/authorize",
        zlibrary = NULL,
        api_key = NULL,
        userid = NULL,
        username = NULL,
        token = NULL, # only used for oauth authorization
        access = NULL,
        groups = NULL,
        key_cached = NULL,
        backoff_startup = NULL,
        backoff_duration = NULL,
        params = NULL,
        reset = function() {
            private$zlibrary <- NULL
            private$api_key <- NULL
            private$userid <- NULL
            private$username <- NULL
            private$token <- NULL
            private$access <- NULL
            private$groups <- NULL
            private$key_cached <- NULL
            private$backoff_startup <- NULL
            private$backoff_duration <- NULL
        },
        has_full_key_info = function() {
            !is.null(private$userid) &&
                !is.null(private$username) &&
                !is.null(private$access)
        },
        complete_key_info = function() {
            req <- private$request("keys", private$api_key)
            resp <- private$req_perform(req)
            data <- httr2::resp_body_json(resp)
            private$userid <- as.character(.subset2(data, "userID"))
            private$username <- as.character(.subset2(data, "username"))
            private$access <- .subset2(data, "access")
        },
        #' @importFrom rlang caller_env
        ensure_key = function(call = caller_env()) {
            if (is.null(private$api_key)) {
                cli::cli_abort(
                    c(
                        paste(
                            "The API key is not set. Please set it before making the request.",
                            "You can set the key using one of the following methods:"
                        ),
                        "i" = "{.fn $key_set}: to set an API key manually.",
                        "i" = "{.fn $key_oauth}: to authenticate via OAuth.",
                        "i" = "{.fn $key_read}: to read from the cached API key."
                    ),
                    call = call
                )
            }
        },
        request = function(..., library = NULL, query = NULL, method = NULL) {
            # Maybe some requests don't need the api key? we don't requre
            # `api_key` here.
            req <- httr2::request(private$api)
            if (!is.null(library)) req <- library_prefix(req, library)
            req <- httr2::req_url_path_append(req, ...)
            if (!is.null(query)) req <- httr2::req_url_query(req, !!!query)
            req <- httr2::req_user_agent(req, user_agent())
            req <- httr2::req_headers(req, "zotero-api-version" = "3")
            if (!is.null(private$api_key)) {
                req <- httr2::req_auth_bearer_token(req, private$api_key)
            }
            if (!is.null(method)) req <- httr2::req_method(req, method)

            # Rate Limiting:
            # https://www.zotero.org/support/dev/web_api/v3/basics#rate_limiting
            #
            # 1. Error handling for responses with `backoff`
            #
            # 2. If a client has made too many requests within a given time
            # period or is making too many concurrent requests, the API may
            # return `429` Too Many Requests, potentially with a `Retry-After`:
            # <seconds> header. Clients receiving a `429` should wait at least
            # the number of seconds indicated in the header before making
            # further requests, or to perform an exponential backoff if
            # `Retry-After` isn't provided. They should also reduce their
            # overall request rate and/or concurrency to avoid repeatedly
            # getting `429`s, which may result in stricter throttling or
            # temporary blocks.
            httr2::req_retry(req,
                max_tries = 3L,
                is_transient = function(resp) {
                    httr2::resp_is_error(resp) &&
                        # `Retry-After` can also be included with 503 Service
                        # Unavailable responses when the server is undergoing
                        # maintenance. But we won't retry it.
                        (httr2::resp_status(resp) == 429L ||
                            # For responses with backoff
                            httr2::resp_header_exists(resp, "Backoff"))
                },
                after = function(resp) {
                    backoff <- httr2::resp_header(resp, "Backoff")
                    retry_backoff <- httr2::resp_header(resp, "Retry-After")
                    if (!is.null(backoff) && !is.null(retry_backoff)) {
                        backoff <- as.integer(backoff)
                        retry_backoff <- as.integer(retry_backoff)
                        max(backoff, retry_backoff)
                    } else if (is.null(backoff) && is.null(retry_backoff)) {
                        NA # Exponential Backoff
                    } else if (is.null(backoff)) {
                        as.integer(retry_backoff)
                    } else {
                        as.integer(backoff)
                    }
                }
            )
        },
        backoff_setup = function(resp) {
            # If the API servers are overloaded, the API may include a
            # `Backoff`: <seconds> HTTP header in responses, indicating that the
            # client should perform the minimum number of requests necessary to
            # maintain data consistency and then refrain from making further
            # requests for the number of seconds indicated. `Backoff` can be
            # included in any response, including successful ones.
            #
            # We only setup backup in successful response
            backoff <- httr2::resp_header(resp, "Backoff")
            if (!is.null(backoff)) {
                private$backoff_startup <- Sys.time()
                private$backoff_duration <- as.integer(backoff)
            }
        },
        backoff_reset = function() {
            private$backoff_startup <- NULL
            private$backoff_duration <- NULL
        },
        backoff_reminder = function() {
            reminder <- private$backoff_duration -
                as.integer(Sys.time() - private$backoff_startup)
            max(reminder, 0L)
        },
        backoff_wait = function() {
            if (!is.null(private$backoff_startup)) {
                total <- private$backoff_reminder()
                if (total > 0L) {
                    cli::cli_progress_bar(
                        "Throttling backoff",
                        total = total, clear = TRUE
                    )
                    while (TRUE) {
                        reminder <- private$backoff_reminder()
                        if (reminder > 0L) {
                            cli::cli_progress_update(set = total - reminder)
                        }
                        break
                    }
                    cli::cli_progress_done()
                }
                private$backoff_reset()
            }
        },
        req_perform = function(req, ...) {
            private$backoff_wait() # Wait for backoff of last request
            resp <- httr2::req_perform(req, ...)
            private$backoff_setup(resp) # setup backoff for next request
            resp
        },
        query = function(params = NULL, ...) {
            if (is.null(params)) {
                params <- private$params
            } else {
                params <- merge(private$params, params)
            }
            query_params(params, ...)
        },
        req_collection = function(collection, ..., call = caller_env()) {
            assert_string(collection, allow_empty = FALSE, call = call)
            private$request(
                "collections", collection, ...,
                library = self$library()
            )
        },
        req_item = function(item, ..., call = caller_env()) {
            assert_string(item, allow_empty = FALSE, call = call)
            private$request("items", item, ..., library = self$library())
        }
    )
)

#' Zotero Library
#'
#' @description
#' This function creates a `zotero_library` object, which represents a specific
#' Zotero library.  A library is identified by a `user ID` or `group ID`, and
#' its type is either `"user"` or `"group"`. The `zotero_library` object is used
#' when specifying the library for API requests to [Zotero] instance, ensuring
#' that the request is scoped to a specific user or group library.
#'
#' @param library_id A string representing either a `user ID` or `group ID` for
#'   the library. This is the unique identifier for the Zotero library.
#' @param library_type A string that specifies the type of the library. It can
#' either be:
#'   - `"user"`: Represents a user library.
#'   - `"group"`: Represents a group library.
#'
#' @return A `zotero_library` object.
#' @export
zotero_library <- function(library_id, library_type) {
    if (!(is.character(library_id) || is.numeric(library_id)) ||
        (length(library_id) != 1L || is.na(library_id))) {
        cli::cli_abort("{.arg library_id} must be a single string")
    }
    library_type <- rlang::arg_match0(library_type, c("user", "group"))
    structure(
        list(id = as.character(library_id), type = library_type),
        class = "zotero_library"
    )
}

library_prefix <- function(request, library) {
    httr2::req_url_path_append(
        request,
        paste0(.subset2(library, "type"), "s"),
        .subset2(library, "id")
    )
}

#' @export
print.zotero_library <- function(x, ...) {
    cat("<", .subset2(x, "type"), ": ", .subset2(x, "id"), ">\n", sep = "")
    invisible(x)
}
