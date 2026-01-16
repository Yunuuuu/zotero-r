credential_dir <- function() cache_dir("credential")

credential_userids_path <- function() {
    file.path(cache_dir(), "credential-userids.rds", fsep = "/")
}

#' @importFrom rlang hash
credential_key_path <- function(userid) {
    file.path(credential_dir(), hash(userid), fsep = "/")
}

credential_get <- function(userid = NULL) {
    if (is.null(userid)) {
        key <- NULL
    } else {
        key <- tryCatch(
            httr2::secret_read_rds(
                credential_key_path(userid),
                I(httr2_fun("unobfuscate")(.secret$obfuscate_key()))
            ),
            error = function(cnd) NULL
        )
        if (is.null(key)) {
            cli::cli_abort(sprintf(
                "No cached credential file found for userID: {.field %s}.",
                userid
            ))
        }
    }
    if (is.null(key)) {
        credential_files <- dir(credential_dir(), full.names = TRUE)
        credential_userids_file <- credential_userids_path()
        if (length(credential_files)) {
            oauth_userids <- tryCatch(
                readRDS(credential_userids_file),
                error = NULL
            )
            if (is.null(oauth_userids)) {
                ordering <- order(
                    file.mtime(credential_files),
                    decreasing = TRUE
                )
                credential_files <- credential_files[ordering]
            } else {
                credential_files <- credential_key_path(unique(oauth_userids))
            }
            missing <- 0L
            for (path in credential_files) {
                key0 <- tryCatch(
                    httr2::secret_read_rds(
                        path,
                        I(httr2_fun("unobfuscate")(.secret$obfuscate_key()))
                    ),
                    error = function(cnd) NULL
                )
                if (!is.null(key0)) {
                    key <- key0
                    break
                }
                missing <- missing + 1L
            }
            if (!is.null(oauth_userids) && missing > 0L) {
                oauth_userids <- oauth_userids[-seq_len(missing)]
                if (length(oauth_userids)) {
                    saveRDS(oauth_userids, credential_userids_file)
                } else if (unlink(credential_userids_file, force = TRUE)) {
                    cli::cli_warn(sprintf(
                        "Unable to remove file {.path %s}",
                        credential_userids_file
                    ))
                }
            }
        } else if (file.exists(credential_userids_file)) {
            if (unlink(credential_userids_file, force = TRUE)) {
                cli::cli_warn(sprintf(
                    "Unable to remove file {.path %s}",
                    credential_userids_file
                ))
            }
        }
    }
    if (is.null(key)) cli::cli_abort("No cached credential file found")
    key
}
