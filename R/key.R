zotero_key <- function() the$key_cache

#' Zotero API Key Management and OAuth Authorization
#'
#' This function manages API key handling and OAuth authorization for the Zotero
#' API.
#'
#' @param api_key Optional API key. If provided, the function will set the API
#' key in the memory and return without performing OAuth authorization.
#'
#' @param oauth_userid Optional user ID. Used to retrieve a cached OAuth token
#' specific to the user. If provided, the function will search for a cached
#' token associated with this user ID. If not provided, the function will use
#' the last used token key file or the most recently available cached token.
#' @export
zotero_autho <- function(api_key = NULL, oauth_userid = NULL, reauth = FALSE) {
    if (!is.null(api_key)) {
        assert_string(api_key)
        the$key_cache <- zotero_api_key(api_key)
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
        the$key_cache <- zotero_oauth_key()
    } else {
        the$key_cache <- httr2::secret_read_rds(
            path,
            I(httr2_fun("unobfuscate")(.secret$obfuscate_key()))
        )
    }

    # cache the OAuth token for future use
    httr2::secret_write_rds(
        the$key_cache, oauth_token_path(the$key_cache["userID"]),
        I(httr2_fun("unobfuscate")(.secret$obfuscate_key()))
    )
    cli::cli_inform(c(
        "v" = sprintf(
            "OAuth authorization for userID: {.field %s}",
            the$key_cache["userID"]
        )
    ))

    # Save the user ID of the OAuth key for future reference
    oauth_userids_file <- oauth_userids_path()
    if (file.exists(oauth_userids_file)) {
        oauth_userids <- readRDS(oauth_userids_file)
    } else {
        oauth_userids <- NULL
    }
    oauth_userids <- unique(c(the$key_cache["userID"], oauth_userids))
    saveRDS(oauth_userids, oauth_userids_file)
    return(invisible(NULL))
}

zotero_revoke <- function(oauth_userid = NULL) {
    if (is.null(oauth_userid)) {
        key <- zotero_key()
    }
    if (is.null(key) && !is.null(path <- zotero_oauth_path(oauth_userid))) {
        key <- httr2::secret_read_rds(
            path,
            I(httr2_fun("unobfuscate")(.secret$obfuscate_key()))
        )
    }
    if (!is.null(key)) {
        req <- httr2::req_url_path_append(
            api_req(), "keys", key["oauth_token_secret"]
        )
        req <- httr2::req_method(req, "DELETE")
        resp <- httr2::req_perform(zotero_autho_key(key, req))
        if (!httr2::resp_is_error(resp)) {
            oauth_userids_file <- oauth_userids_path()
            if (file.exists(oauth_userids_file)) {
                oauth_userids <- readRDS(oauth_userids_file)
                oauth_userids <- setdiff(oauth_userids, key["userID"])
                if (length(oauth_userids)) {
                    saveRDS(oauth_userids, oauth_userids_file)
                } else if (unlink(oauth_userids_file, force = TRUE)) {
                    cli::cli_warn(
                        "cannot remove file {.path {oauth_userids_file}}"
                    )
                }
            }
            oauth_token_file <- oauth_token_path(key["userID"])
            if (file.exists(oauth_token_file) &&
                unlink(oauth_token_file, force = TRUE)) {
                cli::cli_warn("cannot remove file {.path {oauth_token_file}}")
            }
            cli::cli_inform(c(
                "v" = sprintf(
                    "Revoked OAuth authorization for userID: {.field %s}",
                    key["userID"]
                )
            ))
        }
    }
}

#' @importFrom rlang hash
oauth_token_path <- function(userid) {
    file.path(cache_dir(), paste0(hash(userid), "-token.rds"), fsep = "/")
}

oauth_userids_path <- function() {
    file.path(cache_dir(), "oauth-userids.rds", fsep = "/")
}

zotero_oauth_path <- function(oauth_userid = NULL, call = caller_env()) {
    if (is.null(oauth_userid)) {
        path <- NULL
    } else {
        assert_string(oauth_userid, call = call)
        path <- oauth_token_path(oauth_userid)
        if (!file.exists(path)) {
            cli::cli_abort("No cached OAuth file found for user ID {.field {oauth_userid}}.")
        }
    }
    if (is.null(path)) {
        token_files <- dir(
            cache_dir(),
            recursive = TRUE,
            full.names = TRUE,
            pattern = "-token\\.rds$"
        )
        if (length(token_files)) {
            oauth_userids_file <- oauth_userids_path()
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
                    } else {
                        unlink(oauth_userids_file, force = TRUE)
                    }
                }
            } else {
                ordering <- order(file.mtime(token_files), decreasing = TRUE)
                path <- token_files[ordering[1L]]
            }
        }
    }
    path
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
    oauth_key <- zotero_oauth_acess(client, token, verifier)
    structure(oauth_key, class = "zotero_oauth_key")
}

#' @export
print.zotero_oauth_key <- function(x, ...) {
    cat("<zotero_oauth_key> for <userID: ", x["userID"], ">", "\n",
        append = TRUE, sep = ""
    )
    invisible(x)
}

zotero_oauth_client <- function(redirect_uri = NULL) {
    if (is.null(redirect_uri)) redirect_uri <- httr2::oauth_redirect_uri()
    redirect <- httr2_fun("normalize_redirect_uri")(redirect_uri)
    redirect$local_display <- .Platform$GUI == "AQUA" ||
        grepl("^(localhost|):", Sys.getenv("DISPLAY"))
    structure(list(
        secret = .secret$client_secret,
        key = .secret$client_key,
        redirect = redirect
    ), class = "zotero_oauth_client")
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
    token_values <- vapply(
        token_data, .subset, character(1L), 2L,
        USE.NAMES = FALSE
    )
    names(token_values) <- token_names
    token_values
}

zotero_oauth_authorize <- function(client, token) {
    req <- httr2::req_url_query(
        httr2::request("https://www.zotero.org/oauth/authorize"),
        oauth_token = token["oauth_token"],
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

zotero_oauth_acess <- function(client, token, verifier) {
    req <- httr2::request("https://www.zotero.org/oauth/access")
    req <- httr2::req_method(req, "POST")
    req <- httr2::req_headers(req, Authorization = oauth_header(oauth_params(
        req$method, req$url,
        key = httr2_fun("unobfuscate")(client$key()),
        secret = httr2_fun("unobfuscate")(client$secret()),
        redirect = client$redirect,
        token = token["oauth_token"],
        token_secret = token["oauth_token_secret"],
        verifier = verifier
    )))
    api_keys <- httr2::resp_body_string(httr2::req_perform(req))
    api_keys <- strsplit(
        .subset2(strsplit(api_keys, "&", fixed = TRUE), 1L),
        "=",
        fixed = TRUE
    )
    key_names <- vapply(
        api_keys, .subset, character(1L), 1L,
        USE.NAMES = FALSE
    )
    key_values <- vapply(
        api_keys, .subset, character(1L), 2L,
        USE.NAMES = FALSE
    )
    names(key_values) <- key_names
    key_values
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
