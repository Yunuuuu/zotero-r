#' Zotero instance
#'
#' @param tags A boolean value indicating whether to retrieve the tags
#' associated with the request.
#' @param collection A specific collection in the library.
#' @param item A specific saved search in the library.
#' @param search A specific saved search in the library.
#' @seealso
#' A full list of methods can be found here:
#' <http://www.zotero.org/support/dev/server_api>
#' @export
Zotero <- R6::R6Class(
    "Zotero",
    public = list(

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
                private$request, private$authorize, private$access
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
                req <- self$request("users", self$key_userid(), "groups")
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
            req <- self$request("keys", private$api_key)
            req <- httr2::req_method(req, "DELETE")
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

        #' @description Determine or Set the global searching parameters
        #'
        #' @param sort The name of the field by which entries are sorted.
        #' @param direction The sorting direction of the field specified in the
        #' sort parameter. One of `"asc"` or `"desc"`.
        #' @param limit The maximum number of results to return with a single
        #' request. Required for export formats. An integer between 1-100.
        #' @param start The index of the first result. Combine with the `limit`
        #' parameter to select a slice of the available results.
        #' @param item_search,tag_search A [`zotero_search()`] object to
        #' refine the item/tag searching.
        #' @param format Format of the response.
        #' @param format_includes Formats to include in the response, multiple
        #' formats can be specified.
        #' @param format_contents The format of the Atom response's <content>
        #' node, multiple formats can be specified.
        #' @param style Citation style for formatted references. You can provide
        #' either the name of a style (e.g., `"apa"`) or a URL to a custom CSL
        #' file. Only valid when `format = "bib"`, or when `format_includes` or
        #' `format_contents` contains `"bib"` or `"citation"`.
        #' @param linkwrap A boolean indicating whether URLs and DOIs should be
        #' returned as links. Only valid when `format = "bib"`, or when
        #' `format_includes` or `format_contents` contains `"bib"` or
        #' `"citation"`.
        #' @param locale A character string specifying the locale to use for
        #' bibliographic formatting (e.g., `"en-US"`). Only valid when `format =
        #' "bib"`, or when `format_includes` or `format_contents` contains
        #' `"bib"` or `"citation"`.
        parameters = function(sort = NULL, direction = NULL,
                              limit = NULL, start = NULL,
                              # Search Parameters
                              item_search = NULL, tag_search = NULL,
                              # The following parameters affect the format of
                              # data returned from read requests
                              format = NULL,
                              format_includes = NULL,
                              format_contents = NULL,
                              style = NULL, linkwrap = NULL, locale = NULL) {
            assert_string(sort, allow_empty = FALSE, allow_null = TRUE)
            if (!is.null(direction)) {
                direction <- rlang::arg_match0(direction, c("asc", "desc"))
            }
            assert_number_whole(limit, min = 1, max = 100, allow_null = TRUE)
            assert_number_whole(start, min = 0, allow_null = TRUE)
            assert_s3_class(item_search, "zotero_search")
            assert_s3_class(tag_search, "zotero_search")

            # General Parameters
            if (!is.null(format)) {
                format <- rlang::arg_match0(format, c(
                    "atom", "bib", "json", "keys", "versions",
                    # Item Export Formats
                    # The following bibliographic data formats can be used as
                    # `format`, `include`, and `content` parameters for items
                    # requests:
                    "bibtex", "biblatex", "bookmarks", "coins",
                    "csljson", "csv", "mods", "refer", "rdf_bibliontology",
                    "rdf_dc", "rdf_zotero", "ris", "tei", "wikipedia"
                ))
            }

            # Parameters for "format=json"
            if (!is.null(format_includes)) {
                format_includes <- unique(as.character(format_includes))
                format_includes <- rlang::arg_match0(format_includes, c(
                    "bib", "citation", "data",
                    # Item Export Formats
                    # The following bibliographic data formats can be used as
                    # `format`, `include`, and `content` parameters for items
                    # requests:
                    "bibtex", "biblatex", "bookmarks", "coins",
                    "csljson", "csv", "mods", "refer", "rdf_bibliontology",
                    "rdf_dc", "rdf_zotero", "ris", "tei", "wikipedia"
                ))
            }

            # Parameters for "format=atom"
            if (!is.null(format_contents)) {
                format_contents <- unique(as.character(format_contents))
                format_contents <- rlang::arg_match0(format_contents, c(
                    "bib", "citation", "html", "json", "none",
                    # Item Export Formats
                    # The following bibliographic data formats can be used as
                    # `format`, `include`, and `content` parameters for items
                    # requests:
                    "bibtex", "biblatex", "bookmarks", "coins",
                    "csljson", "csv", "mods", "refer", "rdf_bibliontology",
                    "rdf_dc", "rdf_zotero", "ris", "tei", "wikipedia"
                ))
            }
            # Parameters for "format=bib", "include/content=bib",
            # "include/content=citation": style, linkwrap, locale
            assert_bool(style, allow_empty = FALSE, allow_null = TRUE)
            assert_bool(linkwrap, allow_null = TRUE)
            assert_bool(locale, allow_empty = FALSE, allow_null = TRUE)
            params <- list(
                sort = sort, direction = direction,
                limit = limit, start = start,
                item_search = item_search, tag_search = tag_search,
                format = format,
                format_includes = format_includes,
                format_contents = format_contents,
                style = style, linkwrap = linkwrap, locale = locale
            )
            params <- params[
                !vapply(params, is.null, logical(1L), USE.NAMES = FALSE)
            ]
            if (length(params) == 0L) return(private$params) # styler: off
            private$params[names(params)] <- params
            invisible(self)
        },

        #' @description Make a request to the Zotero API
        #' @details
        #' This method constructs a request of the Zotero API. It allows you to
        #' specify the URL path components and optional query parameters, and
        #' includes support for prefixing library-specific paths (e.g.,
        #' `/users/<userID>` or `/groups/<groupID>`) when interacting with data
        #' from specific libraries.
        #' @param ... Character strings representing the path components to
        #' append to the Zotero API base URL.
        #' @param library A [`zotero_library()`] object. If provided, the
        #' request URL will be prefixed with the relevant library path
        #' (`/users/<userID>` or `/groups/<groupID>`), ensuring that the request
        #' is scoped to a specific library.
        #' @param query Optional named list of query parameters to be added to
        #' the request URL.
        #' @return A `httr2` [request][httr2::request] object that can be used
        #' to send the API request.
        request = function(..., library = NULL, query = NULL) {
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

            # Rate Limiting:
            # https://www.zotero.org/support/dev/web_api/v3/basics#rate_limiting
            #
            # 1. Error handling for responses with backoff
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
                        # For Retry-After
                        #
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

        #' @description Collections in the library
        collections = function() {
            req <- self$request("collections", library = self$library())
            private$req_perform(req)
        },

        #' @description Top-level collections in the library
        collections_top = function() {
            req <- self$request("collections", "top", library = self$library())
            private$req_perform(req)
        },

        #' @description A specific collection in the library
        collection = function(collection) {
            req <- private$req_collection(collection)
            private$req_perform(req)
        },

        #' @description Subcollections within a specific collection in the
        #' library
        collection_subgroups = function(collection) {
            req <- private$req_collection(collection, "collections")
            private$req_perform(req)
        },

        #' @description Tags associated with a specific collection in the
        #' library
        collection_tags = function(collection) {
            req <- private$req_collection(collection, "tags")
            private$req_perform(req)
        },

        #' @description Items within a specific collection in the library
        collection_items = function(collection) {
            req <- private$req_collection(collection, "items")
            private$req_perform(req)
        },

        #' @description Tags associated with the Items within a specific
        #' collection in the library
        collection_items_tags = function(collection) {
            req <- private$req_collection(collection, "items", "tags")
            private$req_perform(req)
        },

        #' @description Top-level items within a specific collection in the
        #' library
        collection_items_top = function(collection) {
            req <- private$req_collection(collection, "items", "top")
            private$req_perform(req)
        },

        #' @description Tags associated with the top-level items within a
        #' specific collection in the library
        collection_items_top_tags = function(collection) {
            req <- private$req_collection(collection, "items", "top", "tags")
            private$req_perform(req)
        },

        #' @description All items in the library, excluding trashed items
        items = function() {
            req <- self$request("items", library = self$library())
            private$req_perform(req)
        },

        #' @description Tags associated all items in the library, excluding
        #' trashed items
        items_tags = function() {
            req <- self$request("items", "tags", library = self$library())
            private$req_perform(req)
        },

        #' @description Top-level items in the library, excluding trashed items
        items_top = function() {
            req <- self$request("items", "top", library = self$library())
            private$req_perform(req)
        },

        #' @description Tags associated with the top-level items in the library
        items_top_tags = function() {
            req <- self$request(
                "items", "top", "tags",
                library = self$library()
            )
            private$req_perform(req)
        },

        #' @description Items in the trash
        items_trash = function() {
            req <- self$request("items", "trash", library = self$library())
            private$req_perform(req)
        },

        #' @description Tags associated with the items in the trash
        items_trash_tags = function() {
            req <- self$request(
                "items", "trash", "tags",
                library = self$library()
            )
            private$req_perform(req)
        },

        #' @description A specific item in the library
        item = function(item) {
            req <- private$req_item(item)
            private$req_perform(req)
        },

        #' @description Tags associated with a specific item in the library
        item_tags = function(item) {
            req <- private$req_item(item, "tags")
            private$req_perform(req)
        },

        #' @description Child items under a specific item
        item_children = function(item) {
            req <- private$req_item(item, "children")
            private$req_perform(req)
        },

        #' @description Items in My Publications
        publication_items = function() {
            req <- self$request(
                "publications", "items",
                library = self$library()
            )
            private$req_perform(req)
        },

        #' @description Tags associated with the items in My Publications
        publication_items_tags = function() {
            req <- self$request(
                "publications", "items", "tags",
                library = self$library()
            )
            private$req_perform(req)
        },

        #' @description Get all saved searches in the library
        #' @details Only get the saved searches, not search results.
        saved_searches = function() {
            req <- self$request("searches", library = self$library())
            private$req_perform(req)
        },

        #' @description Get a specific saved search in the library
        #' @details Only get the saved searches, not search results.
        saved_search = function(search) {
            assert_string(search, allow_empty = FALSE)
            req <- self$request(
                "searches", search,
                library = self$library()
            )
            private$req_perform(req)
        },

        #' @description All tags in the library
        tags = function() {
            req <- self$request("tags", library = self$library())
            private$req_perform(req)
        }
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
            req <- self$request("keys", private$api_key)
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
        req_collection = function(collection, ..., call = caller_env()) {
            assert_string(collection, allow_empty = FALSE, call = call)
            self$request("collections", collection,
                ...,
                library = self$library()
            )
        },
        req_item = function(item, ..., call = caller_env()) {
            assert_string(item, allow_empty = FALSE, call = call)
            self$request("items", item, ..., library = self$library())
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

#' Searching Parameters for Zotero API
#'
#' @param quick A character string for a quick search. Use the `mode` parameter
#' to change the search mode. Currently, only phrase searching is supported.
#' @param mode A character string specifying the search mode:
#' - For **items** endpoint, you can use one of the following:
#'   - `"titleCreatorYear"`: Search by title, creator, and year.
#'   - `"everything"`: Search across all fields for items.
#' - For **tags** endpoint, you can use one of the following:
#'   - `"contains"`: Tag search mode where the query string must be contained in
#'     the tag.
#'   - `"startsWith"`: Tag search mode where the query string must match the
#'     beginning of the tag.
#' @param include_tag A character vector specifying the tags. Supports Boolean
#' searches (AND, OR, NOT). See the `Boolean Searches` section for details.
#' @param include_items A character vector of item keys. Valid only for item
#' requests. You can specify up to 50 item keys in a single request.
#' @param include_item_type A character vector specifying item types. Supports
#' Boolean searches (AND, OR, NOT). See the `Boolean Searches` section for
#' details.
#' @param since An integer representing a specific library version. Only items
#' modified after the specified version (from a previous
#' **Last-Modified-Version** header) will be returned.
#' @section Boolean searches:
#' - `include_item_type = "book"`
#' - `include_item_type = "book || journalArticle"` (OR)
#' - `include_item_type = "-attachment"` (NOT)
#' - `include_tag = "foo"`
#' - `include_tag = "foo bar"` (tag with space)
#' - `include_tag = c("foo", "bar")`: Equivalent to`"tag=foo&tag=bar"` (AND)
#' - `include_tag = "foo bar || bar"` (OR)
#' - `include_tag = "-foo"` (NOT)
#' - `include_tag = "\-foo"` (literal first-character hyphen)
zotero_search <- function(quick = NULL, mode = NULL,
                          include_tag = NULL,
                          include_items = NULL,
                          include_item_type = NULL,
                          since = NULL) {
    assert_string(quick, allow_empty = FALSE, allow_null = TRUE)
    if (!is.null(include_tag)) {
        include_tag <- as.character(include_tag)
        if (anyNA(include_tag)) {
            cli::cli_abort("{.arg include_tag} cannot contain missing value.")
        }
    }
    if (!is.null(mode)) {
        mode <- rlang::arg_match0(mode, c(
            "titleCreatorYear", "everything",
            "contains", "startsWith"
        ))
    }
    if (!is.null(include_items)) include_items <- as.character(include_items)
    if (!is.null(include_item_type)) {
        include_item_type <- as.character(include_item_type)
        if (anyNA(include_item_type)) {
            cli::cli_abort("{.arg include_item_type} cannot contain missing value.")
        }
    }
    assert_number_whole(since, min = 0, allow_null = TRUE)
    structure(
        list(
            quick = quick, mode = mode,
            include_tag = include_tag,
            include_items = include_items,
            include_item_type = include_item_type,
            since = since
        ),
        class = "zotero_search"
    )
}

#' Perform the Zotero API Request
#'
#' This function executes a Zotero API request created by [`Zotero`]. It uses
#' method dispatch to handle different types of request execution based on the
#' input. If a single request is provided, it performs the request. If a list of
#' requests is provided, it performs the requests in parallel.
#'
#' @param req A httr2 [request][httr2::request] or a list of
#'   [request][httr2::request] objects created by [`Zotero`].
#' @param ... Additional arguments passed to method dispatch.
#'  - When `req` is a single request, these arguments are passed to
#'    [`httr2::req_perform()`].
#'  - When `req` is a list of requests, these arguments are passed to
#'    [`httr2::req_perform_parallel()`].
#' @param key Optional authenticated key for the request.
#'
#' @return The response from the Zotero API.
#' @export
zotero_perform <- function(req, ..., key = NULL) UseMethod("zotero_perform")

#' @export
zotero_perform.httr2_request <- function(req, ..., key = NULL) {
    if (!is.null(key)) {
        req <- httr2::req_auth_bearer_token(req, token = key)
    }
    httr2::req_perform(req, ...)
}

#' @export
zotero_perform.list <- function(req, ..., key = NULL) {
    req <- lapply(req, zotero_perform, ..., key = key)
    httr2::req_perform_parallel(req, ...)
}
