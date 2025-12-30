#' Make a Zotero API Request
#'
#' This function constructs a request to the Zotero API. It allows appending
#' paths to the base URL and optionally adding query parameters.
#'
#' @param ... Character strings representing the path components to append
#'   to the base URL (`https://api.zotero.org`).
#' @param query Optional named list of query parameters to add to the request
#'   URL.  Defaults to `NULL`.
#'
#' @return A `httr2` request object that can be passed to `zotero_perform` for
#' execution.
#' @seealso <https://www.zotero.org/support/dev/web_api/v3/basics>
#' @export
zotero_request <- function(..., query = NULL) {
    req <- httr2::request("https://api.zotero.org")
    req <- httr2::req_url_path_append(req, ...)
    if (!is.null(query)) req <- httr2::req_url_query(req, !!!query)
    req
}

#' Perform the Zotero API Request
#'
#' This function executes a Zotero API request created by `zotero_request`. It
#' uses method dispatch to handle different types of request execution based on
#' the input. If a single request is provided, it performs the request. If a
#' list of requests is provided, it performs the requests in parallel.
#'
#' @param req A `httr2` request or a list of `httr2` request objects created by
#'   [`zotero_request()`].
#' @param ... Additional arguments passed to method dispatch.
#'  - When `req` is a single request, these arguments are passed to
#'    [`httr2::req_perform()`].
#'  - When `req` is a list of requests, these arguments are passed to
#'    [`httr2::req_perform_parallel()`].
#' @param key Optional authenticated key for the request, if required. By
#'   default, the function will attempt to use the [global key][zotero_key()].
#'
#' @return The response from the Zotero API.
#' @export
zotero_perform <- function(req, ..., key = NULL) UseMethod("zotero_perform")

#' @export
zotero_perform.httr2_request <- function(req, ..., key = NULL) {
    req <- zotero_header_key(as_key(key), req)
    httr2::req_perform(req, ...)
}

#' @export
zotero_perform.list <- function(req, ..., key = NULL) {
    req <- lapply(req, function(r, key) {
        zotero_header_key(key, r)
    }, key = as_key(key))
    httr2::req_perform_parallel(req, ...)
}

zotero_header_key <- function(key, req) UseMethod("zotero_header_key")

#' @export
zotero_header_key.NULL <- function(key, req) req

#' @export
zotero_header_key.zotero_api_key <- function(key, req) {
    httr2::req_headers(req, Authorization = sprintf("Bearer %s", key))
}

#' @export
zotero_header_key.zotero_oauth_key <- function(key, req) {
    httr2::req_headers(req,
        Authorization = sprintf("Bearer %s", key$oauth_token_secret)
    )
}
