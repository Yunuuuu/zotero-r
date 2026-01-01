#' Zotero instance
#' @export
Zotero <- R6::R6Class(
    "Zotero",
    public = list(

        #' @description Set Zotero API key directly
        #' @param key A string representing the Zotero API key. If provided.
        #'   Visit <https://www.zotero.org/settings/keys> to create a private
        #'   API key.
        key_set = function(key) {
            assert_string(key, allow_empty = FALSE)
            private$reset()
            private$api_key <- key
            private$cached <- FALSE
            invisible(self)
        },

        #' @description OAuth authorization for the Zotero API
        #' @details This method must be used in an interactive session
        key_oauth = function() {
            if (!interactive()) {
                cli::cli_abort("OAuth authorization requires an interactive session.")
            }
            key_data <- zotero_oauth_token(
                private$request,
                private$authorize,
                private$access
            )
            private$reset()
            private$api_key <- .subset2(key_data, "oauth_token_secret")
            private$userid <- .subset2(key_data, "userid")
            private$username <- .subset2(key_data, "username")
            private$token <- .subset2(key_data, "oauth_token")
            private$cached <- FALSE
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
        #'   function will attempt to use the last key used. For your user ID,
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
            private$cached <- TRUE
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
            private$cached <- TRUE

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
                resp <- httr2::req_perform(req)
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
            resp <- httr2::req_perform(req)
            status <- httr2::resp_status(resp)

            # Authentication errors (e.g., invalid API key or insufficient
            # privileges) will return a 403 Forbidden
            if (private$cached &&
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
        #' If no `library_id` is provided, the method will return the currently
        #' used library. If `library_id` is set to `NULL`, the library will be
        #' reset to the default.  Otherwise, if a `library_id` is provided,
        #' `library_type` will default to `"group"`, as it is uncommon for users
        #' to set a `user` type with a library ID that differs from the current
        #' API key's user ID.  If a `library_id` is provided with a non-default
        #' `library_type`, the `library_type` (`"user"` or `"group"`) must be
        #' specified.
        #' @param library_id A string representing either a `user ID` or
        #' `group ID` for the library.
        #' @param library_type A string of `"user"` or `"group"` representing
        #' the type for the library.
        #' @return A `zotero_library` object when `library_id` is missing,
        #' otherwise, returns the Zotero instance itself, allowing for method
        #' chaining.
        library = function(library_id, library_type) {
            if (missing(library_id)) {
                if (!missing(library_type)) {
                    cli::cli_warn("{.arg library_type} cannot be used when {.arg library_id} is missing")
                }
                # If no library_id is provided, use the userid by default
                if (is.null(private$library_id)) {
                    library_id <- self$key_userid()
                    library_type <- "user"
                } else {
                    library_id <- private$library_id
                    library_type <- private$library_type
                }
                return(zotero_library(library_id, library_type))
            }
            assert_string(library_id, allow_empty = FALSE, allow_null = TRUE)
            if (is.null(library_id)) {
                if (!missing(library_type)) {
                    cli::cli_warn("{.arg library_type} cannot be used when {.arg library_id} is {.code NULL}")
                }
                library_type <- NULL
            } else if (missing(library_type)) {
                # Default library_type to "group" if missing (as it's uncommon
                # for users to use "user" type)
                library_type <- "group"
            } else {
                library_type <- rlang::arg_match0(
                    library_type,
                    c("user", "group")
                )
            }
            private$library_id <- library_id
            private$library_type <- library_type
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
        #' @param query Optional named list of query parameters to be added to
        #' the request URL.
        #' @param prefix Whether to include the library-specific prefix. If
        #' `TRUE`, the request URL will be prefixed with the relevant library
        #' path (`/users/<userID>` or `/groups/<groupID>`), ensuring that the
        #' request is scoped to a specific library.
        #' @return A `httr2` [request][httr2::request] object that can be used
        #' to send the API request.
        request = function(..., query = NULL, prefix = NULL) {
            # Maybe some requests don't need the api key? we don't requre
            # `api_key` here.
            req <- httr2::request(private$api)
            if (isTRUE(prefix)) req <- private$library_prefix(req)
            req <- httr2::req_url_path_append(req, ...)
            if (!is.null(query)) req <- httr2::req_url_query(req, !!!query)
            if (!is.null(private$api_key)) {
                req <- httr2::req_headers(req,
                    Authorization = sprintf("Bearer %s", private$api_key)
                )
            }
            req
        },

        #' @description Get saved searches from Zotero API
        #' @details Only get the saved searches, not search results.
        #' @param search_key A specific saved search in the library. If `NULL`,
        #' the method will get all saved searches in the library.
        searches = function(search_key = NULL) {
            assert_string(search_key, allow_empty = FALSE, allow_null = TRUE)
            req <- self$request("searches", search_key, prefix = TRUE)
            httr2::req_perform(req)
        }
    ),
    private = list(
        api = "https://api.zotero.org",
        oauth_request = "https://www.zotero.org/oauth/request",
        oauth_access = "https://www.zotero.org/oauth/access",
        oauth_authorize = "https://www.zotero.org/oauth/authorize",
        library_id = NULL,
        library_type = NULL,
        api_key = NULL,
        userid = NULL,
        username = NULL,
        token = NULL, # only used for oauth authorization
        access = NULL,
        groups = NULL,
        cached = NULL,
        reset = function() {
            private$library_id <- NULL
            private$library_type <- NULL
            private$api_key <- NULL
            private$userid <- NULL
            private$username <- NULL
            private$token <- NULL
            private$access <- NULL
            private$groups <- NULL
            private$cached <- NULL
        },
        has_full_key_info = function() {
            !is.null(private$userid) &&
                !is.null(private$username) &&
                !is.null(private$access)
        },
        complete_key_info = function() {
            req <- self$request("keys", private$api_key)
            resp <- httr2::req_perform(req)
            data <- httr2::resp_body_json(resp)
            private$userid <- .subset2(data, "userID")
            private$username <- .subset2(data, "username")
            private$access <- .subset2(data, "access")
        },
        #' @importFrom rlang caller_env
        ensure_key = function(call = caller_env()) {
            if (is.null(private$api_key)) {
                cli::cli_abort(
                    c(
                        paste(
                            "The Zotero API key is not set. Please set it before making the request.",
                            "You can set the key using one of the following methods:"
                        ),
                        "i" = "{.fn $key_set()}: to set an API key manually.",
                        "i" = "{.fn $key_oauth()}: to authenticate via OAuth.",
                        "i" = "{.fn $key_read()}: to read from the cached API key."
                    ),
                    call = call
                )
            }
        },
        # @description Prefixing library-specific paths for the request
        # @details
        # This method includes support for prefixing library-specific paths
        # (e.g., `/users/<userID>` or `/groups/<groupID>`) for the request.
        library_prefix = function(req) {
            library <- self$library()
            httr2::req_url_path_append(
                req,
                paste0(.subset2(library, "type"), "s"),
                .subset2(library, "id")
            )
        }
    )
)

zotero_library <- function(library_id, library_type) {
    structure(
        list(id = library_id, type = library_type),
        class = "zotero_library"
    )
}

#' @export
print.zotero_library <- function(x, ...) {
    cat("<", .subset2(x, "type"), ">", .subset2(x, "id"), "\n", sep = "")
    invisible(x)
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
        req <- httr2::req_headers(req,
            Authorization = sprintf("Bearer %s", key)
        )
    }
    httr2::req_perform(req, ...)
}

#' @export
zotero_perform.list <- function(req, ..., key = NULL) {
    req <- lapply(req, zotero_perform, ..., key = key)
    httr2::req_perform_parallel(req, ...)
}
