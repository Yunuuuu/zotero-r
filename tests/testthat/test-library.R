test_that("zotero_library creates valid objects", {
    lib_user <- zotero_library("12345", "user")
    expect_s3_class(lib_user, "zotero_library")
    expect_equal(lib_user$id, "12345")
    expect_equal(lib_user$type, "user")

    lib_group <- zotero_library(67890, "group")
    expect_equal(lib_group$id, "67890")
    expect_equal(lib_group$type, "group")
})

test_that("zotero_library validates inputs correctly", {
    expect_error(zotero_library(c("123", "456"), "user"), "must be a single string")
    expect_error(zotero_library("123", "invalid_type"))
})

test_that("library_prefix appends correct path based on library type", {
    req <- httr2::request("https://api.zotero.org")

    lib_user <- zotero_library("123", "user")
    req_user <- library_prefix(req, lib_user)
    expect_equal(req_user$url, "https://api.zotero.org/users/123")

    lib_group <- zotero_library("456", "group")
    req_group <- library_prefix(req, lib_group)
    expect_equal(req_group$url, "https://api.zotero.org/groups/456")
})
