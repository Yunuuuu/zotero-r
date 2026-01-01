credential_path <- function(userid) {
    file.path(cache_dir(), paste0(userid, "-credential.rds"), fsep = "/")
}

credential_userids_path <- function() {
    file.path(cache_dir(), "credential-userids.rds", fsep = "/")
}

credential_get <- function(userid = NULL) {
    if (is.null(userid)) {
        path <- NULL
    } else {
        path <- credential_path(userid)
        if (!file.exists(path)) {
            cli::cli_abort(sprintf(
                "No cached credential file found for userID: {.field %s}.",
                userid
            ))
        }
    }
    if (is.null(path)) {
        credential_files <- dir(cache_dir(),
            recursive = TRUE, full.names = TRUE,
            pattern = "-credential\\.rds$"
        )
        credential_userids_file <- credential_userids_path()
        if (length(credential_files)) {
            if (file.exists(credential_userids_file)) {
                oauth_userids <- unique(readRDS(credential_userids_file))
                missing <- 0L
                for (userid in oauth_userids) {
                    path0 <- credential_path(userid)
                    if (file.exists(path0)) {
                        path <- path0
                        break
                    }
                    missing <- missing + 1L
                }
                if (missing > 0L) {
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
            } else {
                ordering <- order(
                    file.mtime(credential_files),
                    decreasing = TRUE
                )
                path <- credential_files[ordering[1L]]
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
    if (is.null(path)) cli::cli_abort("No cached credential file found")
    path
}
