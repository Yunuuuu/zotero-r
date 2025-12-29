pkg_dir <- function(which) {
    dir_create(tools::R_user_dir(pkg_nm(), which), recursive = TRUE)
}

data_dir <- function() pkg_dir("data")

cache_dir <- function() pkg_dir("cache")

config_dir <- function() pkg_dir("config")

cache_token_prune <- function(days = 30L, path = cache_dir()) {
    files <- dir(
        path,
        recursive = TRUE,
        full.names = TRUE,
        pattern = "-token\\.rds$"
    )
    # remove the key file after 30 days
    mtime <- file.mtime(files)
    old <- mtime < (Sys.time() - days * 86400L)
    unlink(files[old], force = TRUE)
}

dir_create <- function(path, ...) {
    if (!dir.exists(path) &&
        !dir.create(path = path, showWarnings = FALSE, ...)) {
        cli::cli_abort("Cannot create directory {.path {path}}")
    }
    invisible(path)
}

httr2_fun <- function(fn, mode = "any") {
    from_namespace("httr2", fn, mode = mode)
}
