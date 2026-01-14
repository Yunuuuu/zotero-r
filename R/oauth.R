zotero_oauth_token <- function(request, authorize, access) {
    client <- zotero_oauth_client()
    # 1. Get an unauthorized request token
    token <- zotero_oauth_request(client, request)

    # 2. Authorize the token
    verifier <- zotero_oauth_authorize(client, token, authorize)

    # 3. Request access token
    # oauth_token
    # oauth_token_secret
    # userID
    # username
    zotero_oauth_access(client, token, verifier, access)
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

zotero_oauth_request <- function(client, request) {
    req <- httr2::request(request)
    req <- httr2::req_method(req, "POST")
    req <- httr2::req_headers(req, Authorization = oauth_header(oauth_params(
        httr2::req_get_method(req), httr2::req_get_url(req),
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

zotero_oauth_authorize <- function(client, token, authorize) {
    req <- httr2::req_url_query(
        httr2::request(authorize),
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

zotero_oauth_access <- function(client, token, verifier, access) {
    req <- httr2::request(access)
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
    token_values
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
