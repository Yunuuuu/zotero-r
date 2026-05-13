test_that("Zotero class initializes correctly", {
    z <- Zotero$new()
    expect_s3_class(z, "Zotero")
    expect_s3_class(z, "R6")
})

test_that("Zotero$key_set handles explicit keys", {
    z <- Zotero$new()
    expect_invisible(z$key_set("test_api_key"))
})

test_that("Zotero$library sets and retrieves library info", {
    z <- Zotero$new()

    # Set a specific group library
    expect_invisible(z$library("789", "group"))

    # Retrieve it
    lib <- z$library()
    expect_s3_class(lib, "zotero_library")
    expect_equal(lib$id, "789")
    expect_equal(lib$type, "group")
})
