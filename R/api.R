api_req <- function() httr2::request("https://api.zotero.org")

api_key <- function(api_key = NULL) {
    if (is.null(api_key)) {
        zotero_key()
    } else {
        zotero_api_key(api_key)
    }
}

zotero_autho_key <- function(key, request) UseMethod("zotero_autho_key")

#' @export
zotero_autho_key.NULL <- function(key, request) request

#' @export
zotero_autho_key.zotero_api_key <- function(key, request) {
    httr2::req_headers(request, Authorization = sprintf("Bearer %s", key))
}

#' @export
zotero_autho_key.zotero_oauth_key <- function(key, request) {
    httr2::req_headers(request,
        Authorization = sprintf("Bearer %s", key["oauth_token_secret"])
    )
}
