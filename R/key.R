#' Retrieve the global Zotero API Key
#'
#' This function returns the global Zotero API key, which is set by
#' [`zotero_auth()`].  The key is used for authenticated requests to the Zotero
#' API.
#'
#' @export
zotero_key <- function() zotero_key_get()

zotero_key_get <- function() the$key_cache
zotero_key_set <- function(value) the$key_cache <- value

#' Zotero API Key Management and OAuth Authorization
#'
#' This function handles both API key management and OAuth authorization for the
#' Zotero API. Users can either provide a private API key directly or
#' authenticate using OAuth. While both methods involve API keys, the private
#' key is typically referred to as the "private API key", while the OAuth
#' credential is referred to as the "OAuth token" within the package.
#'
#' @param api_key A string representing the private API key. If provided, the
#'   function will store the API key in memory and return without performing
#'   OAuth authorization. Visit
#'   <https://www.zotero.org/settings/security#applications> to create a private
#'   API key.
#'
#' @param oauth_userid Optional user ID. Only used when `api_key` is `NULL`. If
#'   provided, the function will attempt to retrieve a cached OAuth token
#'   associated with this user ID. If not provided, the function will attempt to
#'   use the most recent cached token or the last used token file. For your user
#'   ID, visit <https://www.zotero.org/settings/security#applications>.
#'
#' @param reauth Logical. Only used when `api_key` is `NULL`. If `TRUE`, forces
#'   reauthorization even if a cached token is available. Defaults to `FALSE`.
#'   If set to `TRUE`, the function will always initiate the OAuth flow,
#'   ignoring any existing cached tokens.
#'
#' @return The function invisibly returns `NULL` after either setting the API
#'   key or completing the OAuth authorization process. If OAuth is used, the
#'   OAuth token will be cached for future use.
#'
#' @export
zotero_auth <- function(api_key = NULL, oauth_userid = NULL, reauth = FALSE) {
    if (!is.null(api_key)) {
        assert_string(api_key, allow_empty = FALSE)
        zotero_key_set(zotero_api_key(api_key))
        return(invisible(NULL))
    }
    assert_bool(reauth)
    if (reauth || is.null(path <- zotero_oauth_path(oauth_userid))) {
        if (!interactive()) {
            cli::cli_abort(c(
                "OAuth authorization requires an interactive session.",
                i = "Provide an {.arg api_key} to skip OAuth."
            ))
        }
        zotero_key_set(zotero_oauth_key())
    } else {
        zotero_key_set(httr2::secret_read_rds(
            path,
            I(httr2_fun("unobfuscate")(.secret$obfuscate_key()))
        ))
    }

    # cache the OAuth token for future use
    httr2::secret_write_rds(
        zotero_key_get(), oauth_token_path(zotero_key_get()$userID),
        I(httr2_fun("unobfuscate")(.secret$obfuscate_key()))
    )
    cli::cli_inform(c(
        "v" = sprintf(
            "OAuth authorization for userID: {.field %s}",
            zotero_key_get()$userID
        )
    ))

    # Save the user ID of the OAuth key for future reference
    oauth_userids_file <- oauth_userids_path()
    if (file.exists(oauth_userids_file)) {
        oauth_userids <- readRDS(oauth_userids_file)
    } else {
        oauth_userids <- NULL
    }
    oauth_userids <- unique(c(zotero_key_get()$userID, oauth_userids))
    saveRDS(oauth_userids, oauth_userids_file)
    return(invisible(NULL))
}

#' Revoke Zotero OAuth Authorization
#'
#' This function revokes the OAuth authorization for a given user. It also
#' removes the cached OAuth token and deletes any associated token files.
#'
#' @param oauth_userid Optional user ID. If provided, the function will attempt
#'   to find the cached OAuth token for this user. If not provided, the function
#'   will attempt to use the current global OAuth key. For your user ID, visit
#'   <https://www.zotero.org/settings/security#applications>.
#'
#' @export
zotero_revoke <- function(oauth_userid = NULL) {
    if (is.null(oauth_userid)) key <- zotero_key_get()
    if (is.null(key) && !is.null(path <- zotero_oauth_path(oauth_userid))) {
        key <- httr2::secret_read_rds(
            path,
            I(httr2_fun("unobfuscate")(.secret$obfuscate_key()))
        )
    }
    if (!is.null(key)) {
        req <- zotero_request("keys", key$oauth_token_secret)
        req <- httr2::req_method(req, "DELETE")
        req <- httr2::req_error(req, is_error = function(resp) FALSE)
        resp <- zotero_perform(req, key = key)
        status <- httr2::resp_status(resp)
        # Authentication errors (e.g., invalid API key or insufficient
        # privileges) will return a 403 Forbidden
        if (!httr2::resp_is_error(resp) || status == 403L) {
            # reset the global API key
            if (is.null(oauth_userid)) zotero_key_set(NULL)

            # remove the token file
            oauth_token_file <- oauth_token_path(key$userID)
            if (file.exists(oauth_token_file) &&
                unlink(oauth_token_file, force = TRUE)) {
                cli::cli_warn("cannot remove file {.path {oauth_token_file}}")
            }

            # remove the userid
            oauth_userids_file <- oauth_userids_path()
            if (file.exists(oauth_userids_file)) {
                oauth_userids <- readRDS(oauth_userids_file)
                oauth_userids <- setdiff(oauth_userids, key$userID)
                if (length(oauth_userids)) {
                    saveRDS(oauth_userids, oauth_userids_file)
                } else if (unlink(oauth_userids_file, force = TRUE)) {
                    cli::cli_warn(sprintf(
                        "Unable to remove file {.path %s}",
                        oauth_userids_file
                    ))
                }
            }
            cli::cli_inform(c(
                "v" = sprintf(
                    "Revoked OAuth authorization for userID: {.field %s}",
                    key$userID
                )
            ))
        } else {
            cli::cli_abort(c(
                sprintf("Failed to revoke OAuth authorization for userID: {.field %s}. ", key$userID),
                i = sprintf("HTTP Status: %s", status)
            ))
        }
    } else {
        cli::cli_inform("No OAuth key found to revoke.")
    }
    return(invisible(NULL))
}

oauth_token_path <- function(userid) {
    file.path(cache_dir(), paste0(userid, "-token.rds"), fsep = "/")
}

oauth_token_files <- function() {
    dir(cache_dir(),
        recursive = TRUE, full.names = TRUE,
        pattern = "-token\\.rds$"
    )
}

oauth_userids_path <- function() {
    file.path(cache_dir(), "oauth-userids.rds", fsep = "/")
}

zotero_oauth_path <- function(oauth_userid = NULL, call = caller_env()) {
    if (is.null(oauth_userid)) {
        path <- NULL
    } else {
        assert_string(oauth_userid, allow_empty = FALSE, call = call)
        path <- oauth_token_path(oauth_userid)
        if (!file.exists(path)) {
            cli::cli_abort(sprintf(
                "No cached OAuth file found for userID: {.field %s}.",
                oauth_userid
            ))
        }
    }
    if (is.null(path)) {
        token_files <- oauth_token_files()
        oauth_userids_file <- oauth_userids_path()
        if (length(token_files)) {
            if (file.exists(oauth_userids_file)) {
                oauth_userids <- unique(readRDS(oauth_userids_file))
                missing <- 0L
                for (userid in oauth_userids) {
                    path0 <- oauth_token_path(userid)
                    if (file.exists(path0)) {
                        path <- path0
                        break
                    }
                    missing <- missing + 1L
                }
                if (missing > 0L) {
                    oauth_userids <- oauth_userids[-seq_len(missing)]
                    if (length(oauth_userids)) {
                        saveRDS(oauth_userids, oauth_userids_file)
                    } else if (unlink(oauth_userids_file, force = TRUE)) {
                        cli::cli_warn(sprintf(
                            "Unable to remove file {.path %s}",
                            oauth_userids_file
                        ))
                    }
                }
            } else {
                ordering <- order(file.mtime(token_files), decreasing = TRUE)
                path <- token_files[ordering[1L]]
            }
        } else if (file.exists(oauth_userids_file)) {
            if (unlink(oauth_userids_file, force = TRUE)) {
                cli::cli_warn(sprintf(
                    "Unable to remove file {.path %s}",
                    oauth_userids_file
                ))
            }
        }
    }
    path
}

as_key <- function(key) UseMethod("as_key")

#' @export
as_key.NULL <- function(key) zotero_key()

#' @export
as_key.zotero_api_key <- function(key) key

#' @export
as_key.zotero_oauth_key <- function(key) key

#' @export
as_key.character <- function(key) {
    assert_string(key, allow_empty = FALSE)
    zotero_api_key(key)
}

zotero_api_key <- function(api_key) {
    structure(api_key, class = "zotero_api_key")
}

#' @export
print.zotero_api_key <- function(x, ...) {
    cat("<zotero_api_key>", "\n")
    invisible(x)
}

zotero_oauth_key <- function() {
    client <- zotero_oauth_client()
    # 1. Get an unauthorized request token
    token <- zotero_oauth_token(client)

    # 2. Authorize the token
    verifier <- zotero_oauth_authorize(client, token)

    # 3. Request access token
    # oauth_token
    # oauth_token_secret
    # userID
    # username
    zotero_oauth_access(client, token, verifier)
}

#' @export
print.zotero_oauth_key <- function(x, ...) {
    cat("<zotero_oauth_key> for <userID: ", x$userID, ">", "\n",
        append = TRUE, sep = ""
    )
    invisible(x)
}

zotero_oauth_client <- function(redirect_uri = NULL) {
    if (is.null(redirect_uri)) redirect_uri <- httr2::oauth_redirect_uri()
    redirect <- httr2_fun("normalize_redirect_uri")(redirect_uri)
    redirect$local_display <- .Platform$GUI == "AQUA" ||
        grepl("^(localhost|):", Sys.getenv("DISPLAY"))
    structure(
        list(
            secret = .secret$client_secret,
            key = .secret$client_key,
            redirect = redirect
        ),
        class = "zotero_oauth_client"
    )
}

zotero_oauth_token <- function(client) {
    req <- httr2::request("https://www.zotero.org/oauth/request")
    req <- httr2::req_method(req, "POST")
    req <- httr2::req_headers(req, Authorization = oauth_header(oauth_params(
        req$method, req$url,
        key = httr2_fun("unobfuscate")(client$key()),
        secret = httr2_fun("unobfuscate")(client$secret()),
        redirect = client$redirect
    )))
    token_data <- httr2::resp_body_string(httr2::req_perform(req))
    token_data <- strsplit(
        .subset2(strsplit(token_data, "&", fixed = TRUE), 1L),
        "=",
        fixed = TRUE
    )
    token_names <- vapply(
        token_data, .subset, character(1L), 1L,
        USE.NAMES = FALSE
    )
    token_values <- lapply(token_data, .subset, 2L)
    names(token_values) <- token_names
    token_values
}

zotero_oauth_authorize <- function(client, token) {
    req <- httr2::req_url_query(
        httr2::request("https://www.zotero.org/oauth/authorize"),
        oauth_token = token$oauth_token,
        library_access = 1L,
        notes_access = 1L,
        write_access = 1L,
        all_groups = "wirte"
    )
    utils::browseURL(req$url)
    if (client$redirect$localhost &&
        client$redirect$local_display) {
        # Listen on localhost for the result
        parsed <- httr2::url_parse(client$redirect$uri)
        path <- parsed$path %||% "/"
        complete <- FALSE
        data <- NULL
        server <- httpuv::startServer(
            "127.0.0.1", as.integer(parsed$port),
            list(call = function(env) {
                if (!identical(env$PATH_INFO, path)) {
                    return(list(
                        status = 404L,
                        headers = list(`Content-Type` = "text/plain"),
                        body = "Not found"
                    ))
                }
                query <- env$QUERY_STRING
                complete <<- TRUE
                if (is.character(query) && !identical(query, "")) {
                    data <<- query
                }
                list(
                    status = 200L,
                    headers = list(`Content-Type` = "text/plain"),
                    body = "Authentication complete. Please close this page and return to R."
                )
            })
        )
        on.exit(httpuv::stopServer(server))
        cli::cli_inform(c(
            "Waiting for authentication in browser...",
            "Press Esc/Ctrl + C to abort"
        ))
        while (TRUE) {
            httpuv::service()
            if (complete) break
        }
        if (!is.null(data)) {
            cli::cli_abort("Authentication failed; invalid url from server.")
        }
        # TO DO: get oauth_verifier from data
    } else {
        cli::cli_inform(c(
            "Your browser will open. Please authorize the application.",
            "Afterward, you will be redirected to Zotero.",
            "Copy the value of 'oauth_verifier' from the URL and paste it below."
        ))
        openssl::askpass("Enter the 'oauth_verifier': ")
    }
}

zotero_oauth_access <- function(client, token, verifier) {
    req <- httr2::request("https://www.zotero.org/oauth/access")
    req <- httr2::req_method(req, "POST")
    req <- httr2::req_headers(req, Authorization = oauth_header(oauth_params(
        req$method, req$url,
        key = httr2_fun("unobfuscate")(client$key()),
        secret = httr2_fun("unobfuscate")(client$secret()),
        redirect = client$redirect,
        token = token$oauth_token,
        token_secret = token$oauth_token_secret,
        verifier = verifier
    )))
    accessed_token <- httr2::resp_body_string(httr2::req_perform(req))
    accessed_token <- strsplit(
        .subset2(strsplit(accessed_token, "&", fixed = TRUE), 1L),
        "=",
        fixed = TRUE
    )
    token_names <- vapply(
        accessed_token, .subset, character(1L), 1L,
        USE.NAMES = FALSE
    )
    token_values <- lapply(accessed_token, .subset, 2L)
    names(token_values) <- token_names
    structure(token_values, class = "zotero_oauth_key")
}

oauth_params <- function(method, url, key, secret, redirect,
                         private_key = NULL, token = NULL,
                         token_secret = NULL, verifier = NULL) {
    params <- list(
        oauth_consumer_key = key,
        oauth_nonce = nonce(10L),
        oauth_timestamp = as.character(as.integer(Sys.time())),
        oauth_version = "1.0"
    )
    if (is.null(private_key)) {
        params$oauth_signature_method <- "HMAC-SHA1"
    } else {
        params$oauth_signature_method <- "RSA-SHA1"
    }
    if (redirect$localhost && redirect$local_display) {
        params$oauth_callback <- redirect$uri
    } else {
        params$oauth_callback <- "https://www.zotero.org"
    }
    if (!is.null(verifier)) params$oauth_verifier <- verifier
    if (!is.null(token)) params$oauth_token <- token
    params <- params[order(names(params))]
    string <- charToRaw(paste0(
        method, "&",
        oauth_encode(url), "&",
        oauth_encode(oauth_normalize_params(params))
    ))
    if (is.null(private_key)) {
        # Prepare the private key (consumer secret & token secret)
        private_key <- paste0(
            oauth_encode(secret), "&",
            if (!is.null(token_secret)) oauth_encode(token_secret)
        )
        hash <- openssl::sha1(string, key = charToRaw(private_key))
    } else {
        hash <- openssl::signature_create(
            string, openssl::sha1,
            key = charToRaw(private_key)
        )
    }
    params$oauth_signature <- as.character(openssl::base64_encode(hash))
    params
}

oauth_encode <- function(x) {
    chars <- .subset2(strsplit(x, ""), 1L)
    ok <- !grepl("[^A-Za-z0-9_.~-]", chars)
    if (all(ok)) {
        return(x)
    }
    chars[!ok] <- vapply(chars[!ok], function(x) {
        paste0("%", toupper(as.character(charToRaw(x))), collapse = "")
    }, character(1L), USE.NAMES = FALSE)
    paste0(chars, collapse = "")
}

oauth_normalize_params <- function(params) {
    params_nms <- vapply(
        names(params),
        oauth_encode, character(1L),
        USE.NAMES = FALSE
    )
    params_str <- vapply(params, oauth_encode, character(1L), USE.NAMES = FALSE)
    paste(params_nms, params_str, sep = "=", collapse = "&")
}

oauth_header <- function(params) {
    params <- paste0(
        names(params), "=",
        vapply(params, oauth_encode, character(1L), USE.NAMES = FALSE),
        collapse = ", "
    )
    paste("OAuth", params)
}

nonce <- function(length) {
    paste(
        sample(c(letters, LETTERS, 0:9), length, replace = TRUE),
        collapse = ""
    )
}
