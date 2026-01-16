the <- new.env(parent = emptyenv())

rlang::on_load(the$resp_cache <- cachem::cache_disk(dir = cache_dir()))

# Do I need to worry about hash collisions?
# No - even if the user stores a billion urls, the probably of a collision
# is ~ 1e-20: https://preshing.com/20110504/hash-collision-probabilities/
#' @importFrom rlang hash
req_cache_get <- function(req) {
    if (is.null(the$resp_cache) || the$resp_cache$is_destroyed()) {
        cachem::key_missing()
    } else {
        key <- hash(httr2::req_get_url(req))
        the$resp_cache$get(key)
    }
}

resp_cache_set <- function(resp) {
    if (!is.null(the$resp_cache) && !the$resp_cache$is_destroyed()) {
        url <- httr2::resp_url(resp)
        cli::cli_inform("Caching the response for url: {.url {url}}")
        key <- hash(url)
        the$resp_cache$set(key, resp)
    }
}
