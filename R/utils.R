pkg_dir <- function(which) {
    dir_create(tools::R_user_dir(pkg_nm(), which), recursive = TRUE)
}

data_dir <- function() pkg_dir("data")

cache_dir <- function() pkg_dir("cache")

config_dir <- function() pkg_dir("config")

dir_create <- function(path, ...) {
    if (!dir.exists(path) &&
        !dir.create(path = path, showWarnings = FALSE, ...)) {
        cli::cli_abort("Unable to create directory {.path {path}}")
    }
    invisible(path)
}

httr2_fun <- function(fn, mode = "any") from_namespace("httr2", fn, mode = mode)

user_agent <- function(pkg = pkg_nm()) {
    sprintf("%s (%s)", pkg, utils::packageDescription(pkg)$URL)
}

modify_list <- function(old, new) {
    for (i in names(new)) old[[i]] <- new[[i]]
    old
}
