#' Parameters for Zotero API
#'
#' This function constructs a set of parameters to be used when making requests
#' to the Zotero API. It allows users to specify pagination, filtering, search
#' parameters, and format options.
#'
#' @param pagination A [`param_pagination()`] object that defines pagination
#' settings such as the starting index (`start`), the number of results to
#' return (`limit`), and sorting options.
#' @param filter A [`param_filter()`] object that provides filtering options for
#' the search results, such as filtering by item keys, item types, or
#' modification dates.
#' @param item_search A [`param_search()`] object used to refine item searches
#' based on keywords or other criteria.
#' @param tag_search A [`param_search()`] object used to refine tag searches
#' based on specific tags or keywords.
#' @param format A [`param_format()`] object that specifies the desired response
#' format, including options for citation styles, response content, and more.
#' @export
zotero_params <- function(pagination = NULL, filter = NULL,
                          item_search = NULL, tag_search = NULL,
                          format = NULL) {
    assert_s3_class(pagination, "param_pagination", allow_null = TRUE)
    assert_s3_class(filter, "param_filter", allow_null = TRUE)
    assert_s3_class(item_search, "param_search", allow_null = TRUE)
    if (inherits(item_search, "param_search") && !is.null(item_search$mode)) {
        item_search$mode <- rlang::arg_match0(
            item_search$mode,
            c("titleCreatorYear", "everything"),
            error_arg = "item_search$mode"
        )
    }
    assert_s3_class(tag_search, "param_search", allow_null = TRUE)
    if (inherits(tag_search, "param_search") && !is.null(tag_search$mode)) {
        tag_search$mode <- rlang::arg_match0(
            tag_search$mode,
            c("contains", "startsWith"),
            error_arg = "tag_search$mode"
        )
    }
    assert_s3_class(format, "param_search", allow_null = TRUE)
    structure(
        list(
            format = format, pagination = pagination,
            filter = filter, item_search = item_search, tag_search = tag_search
        ),
        class = "zotero_parameters"
    )
}

query_params <- function(params, ...) UseMethod("query_params")

#' @export
merge.zotero_parameters <- function(x, y, ...) {
    for (param_name in names(x)) {
        if (!is.null(x[[param_name]]) && !is.null(y[[param_name]])) {
            param <- merge(x[[param_name]], y[[param_name]], ...)
        } else {
            param <- y[[param_name]] %||% x[[param_name]]
        }
        x[param_name] <- list(param)
    }
    x
}

#' @export
query_params.zotero_parameters <- function(
    params, ...,
    pagination_params = TRUE,
    filter_params = item_search_params || tag_search_params,
    include_trash_param = item_search_params,
    item_search_params = FALSE,
    tag_search_params = FALSE) {
    format <- query_params(params$format %||% param_format())
    if (pagination_params) {
        pagination <- query_params(
            params$pagination %||% param_pagination(),
            format = format$format
        )
    } else {
        pagination <- NULL
    }
    if (filter_params) {
        filter <- query_params(
            params$filter %||% param_filter(),
            include_trash_param = include_trash_param
        )
    } else {
        filter <- NULL
    }
    if (item_search_params) {
        item_search <- query_params(
            params$item_search %||% param_search(),
            mode = "titleCreatorYear"
        )
        if (tag_search_params) {
            item_search <- list(
                itemQ = item_search$q,
                itemQMode = item_search$qmode,
                itemTag = item_search$tag
            )
            item_search <- item_search[
                !vapply(item_search, is.null, logical(1L), USE.NAMES = FALSE)
            ]
        }
    } else {
        item_search <- NULL
    }
    if (tag_search_params) {
        tag_search <- query_params(
            params$tag_search %||% param_search(),
            mode = "contains"
        )
    } else {
        tag_search <- NULL
    }
    c(format, filter, item_search, tag_search, pagination)
}

#' Format parameters for Zotero API
#'
#' @param format Format of the response.
#' @param includes Formats to include in the response, multiple formats can be
#' specified.
#' @param contents The format of the Atom response's <content> node, multiple
#' formats can be specified.
#' @param style Citation style for formatted references. You can provide either
#' the name of a style (e.g., `"apa"`) or a URL to a custom CSL file. Only valid
#' when `format = "bib"`, or when `includes` or `contents` contains `"bib"` or
#' `"citation"`.
#' @param linkwrap A boolean indicating whether URLs and DOIs should be returned
#' as links. Only valid when `format = "bib"`, or when `includes` or `contents`
#' contains `"bib"` or `"citation"`.
#' @param locale A character string specifying the locale to use for
#' bibliographic formatting (e.g., `"en-US"`). Only valid when `format = "bib"`,
#' or when `includes` or `contents` contains `"bib"` or `"citation"`.
param_format <- function(format = NULL, includes = NULL, contents = NULL,
                         style = NULL, linkwrap = NULL, locale = NULL) {
    # General Parameters
    if (!is.null(format)) {
        format <- rlang::arg_match0(format, c(
            "atom", "bib", "json", "keys", "versions",
            # Item Export Formats
            # The following bibliographic data formats can be used as
            # `format`, `include`, and `content` parameters for items
            # requests:
            "bibtex", "biblatex", "bookmarks", "coins",
            "csljson", "csv", "mods", "refer", "rdf_bibliontology",
            "rdf_dc", "rdf_zotero", "ris", "tei", "wikipedia"
        ))
    }

    # Parameters for "format=json"
    if (!is.null(includes)) {
        includes <- unique(as.character(includes))
        includes <- rlang::arg_match0(includes, c(
            "bib", "citation", "data",
            # Item Export Formats
            # The following bibliographic data formats can be used as
            # `format`, `include`, and `content` parameters for items
            # requests:
            "bibtex", "biblatex", "bookmarks", "coins",
            "csljson", "csv", "mods", "refer", "rdf_bibliontology",
            "rdf_dc", "rdf_zotero", "ris", "tei", "wikipedia"
        ))
    }

    # Parameters for "format=atom"
    if (!is.null(contents)) {
        contents <- unique(as.character(contents))
        contents <- rlang::arg_match0(contents, c(
            "bib", "citation", "html", "json", "none",
            # Item Export Formats
            # The following bibliographic data formats can be used as
            # `format`, `include`, and `content` parameters for items
            # requests:
            "bibtex", "biblatex", "bookmarks", "coins",
            "csljson", "csv", "mods", "refer", "rdf_bibliontology",
            "rdf_dc", "rdf_zotero", "ris", "tei", "wikipedia"
        ))
    }

    # Parameters for "format=bib", "include/content=bib",
    # "include/content=citation": style, linkwrap, locale
    assert_string(style, allow_empty = FALSE, allow_null = TRUE)
    assert_bool(linkwrap, allow_null = TRUE)
    assert_string(locale, allow_empty = FALSE, allow_null = TRUE)
    structure(
        list(
            format = format, includes = includes, contents = contents,
            style = style, linkwrap = linkwrap, locale = locale
        ),
        class = "param_format"
    )
}

#' @export
merge.param_format <- function(x, y, ...) y

#' @export
query_params.param_format <- function(params, ...) {
    query <- list()
    query$format <- params$format %||% "json"
    use_style <- query$format == "bib"
    if (query$format == "json") {
        if (is.null(params$includes)) {
            query$include <- "data"
        } else {
            query$include <- paste(params$includes, collapse = ",")
            use_style <- use_style ||
                any(params$includes %in% c("bib", "citation"))
        }
    }
    if (query$format == "atom") {
        if (is.null(params$contents)) {
            query$content <- "html"
        } else {
            query$content <- paste(params$contents, collapse = ",")
            use_style <- use_style ||
                any(params$contents %in% c("bib", "citation"))
        }
    }
    if (use_style) {
        query$style <- params$style %||% "chicago-note-bibliography"
        query$linkwrap <- if (params$linkwrap %||% FALSE) {
            "1"
        } else {
            "0"
        }
        query$locale <- params$locale %||% "en-US"
    }
    query
}

#' Pagination and Soring parameters for Zotero API
#'
#' @param start The index of the first result. Combine with the `limit`
#' parameter to select a slice of the available results.
#' @param limit The maximum number of results to return with a single
#' request. Required for export formats. An integer between 1-100.
#' @param sort The name of the field by which entries are sorted.
#' @param direction The sorting direction of the field specified in the
#' sort parameter. One of `"asc"` or `"desc"`.
#' @export
param_pagination <- function(start = NULL, limit = NULL,
                             sort = NULL, direction = NULL) {
    assert_number_whole(limit, min = 1, max = 100, allow_null = TRUE)
    assert_number_whole(start, min = 0, allow_null = TRUE)
    assert_string(sort, allow_empty = FALSE, allow_null = TRUE)
    if (!is.null(direction)) {
        direction <- rlang::arg_match0(direction, c("asc", "desc"))
    }
    structure(
        list(limit = limit, start = start, sort = sort, direction = direction),
        class = "param_pagination"
    )
}

#' @export
merge.param_pagination <- function(x, y, ...) {
    y <- y[!vapply(y, is.null, logical(1L), USE.NAMES = FALSE)]
    modify_list(x, y)
}

#' @export
query_params.param_pagination <- function(params, ..., format) {
    if (format == "atom") {
        sort <- "dateAdded"
    } else {
        sort <- "dateModified"
    }
    limit <- params$limit %||% 25L
    start <- params$start %||% 0L
    query <- list(sort = sort, limit = limit, start = start)
    # varies by `sort` by default
    if (!is.null(params$direction)) query$direction <- params$direction
    query
}

#' Filtering parameters for Zotero API
#'
#' @param items A character vector of item keys. Valid only for item requests.
#' You can specify up to 50 item keys in a single request.
#' @param item_type A character vector specifying item types. Supports Boolean
#' searches (AND, OR, NOT). See the `Boolean Searches` section for details.
#' @param since An integer representing a specific library version. Only items
#' modified after the specified version (from a previous
#' **Last-Modified-Version** header) will be returned.
#' @param include_trashed Include items in the trash, only valid for Items
#' Endpoints.
#' @section Boolean searches:
#' - `item_type = "book"`
#' - `item_type = "book || journalArticle"` (OR)
#' - `item_type = "-attachment"` (NOT)
#' @export
param_filter <- function(items = NULL, item_type = NULL, since = NULL,
                         include_trashed = NULL) {
    if (!is.null(items)) {
        items <- as.character(items)
        if (anyNA(items)) {
            cli::cli_abort("{.arg items} cannot contain missing value.")
        }
        if (length(items) > 50L) {
            cli::cli_abort("{.arg items} must contain no more than 50 item keys.")
        }
    }
    if (!is.null(item_type)) {
        item_type <- as.character(item_type)
        if (anyNA(item_type)) {
            cli::cli_abort("{.arg item_type} cannot contain missing value.")
        }
    }
    assert_number_whole(since, min = 0, allow_null = TRUE)
    assert_bool(include_trashed, allow_null = TRUE)
    structure(
        list(
            items = items, item_type = item_type, since = since,
            include_trashed = include_trashed
        ),
        class = "param_filter"
    )
}

#' @export
merge.param_filter <- function(x, y, ...) {
    y <- y[!vapply(y, is.null, logical(1L), USE.NAMES = FALSE)]
    modify_list(x, y)
}

#' @export
query_params.param_filter <- function(params, ..., include_trash_param = FALSE) {
    query <- list()
    if (!is.null(params$items)) {
        query$itemKey <- paste(params$items, collapse = ",")
    }
    if (!is.null(itemType <- params$item_type)) {
        names(itemType) <- rep_len("itemType", length(itemType))
        query <- c(query, itemType)
    }
    query$since <- params$since %||% 0L
    if (include_trash_param) {
        query$includeTrashed <- if (params$include_trashed %||% FALSE) {
            "1"
        } else {
            "0"
        }
    }
    query
}

#' Searching parameters for Zotero API
#'
#' @param quick A character string for a quick search. Use the `mode` parameter
#' to change the search mode. Currently, only phrase searching is supported.
#' @param mode A character string specifying the search mode:
#' - For **items** endpoint, you can use one of the following:
#'   - `"titleCreatorYear"`: Search by title, creator, and year.
#'   - `"everything"`: Search across all fields for items.
#' - For **tags** endpoint, you can use one of the following:
#'   - `"contains"`: Tag search mode where the query string must be contained in
#'     the tag.
#'   - `"startsWith"`: Tag search mode where the query string must match the
#'     beginning of the tag.
#' @param tag A character vector specifying the tags. Supports Boolean searches
#' (AND, OR, NOT). See the `Boolean Searches` section for details.
#' @section Boolean searches:
#' - `tag = "foo"`
#' - `tag = "foo bar"` (tag with space)
#' - `tag = c("foo", "bar")`: Equivalent to`"tag=foo&tag=bar"` (AND)
#' - `tag = "foo bar || bar"` (OR)
#' - `tag = "-foo"` (NOT)
#' - `tag = "\-foo"` (literal first-character hyphen)
#' @export
param_search <- function(quick = NULL, mode = NULL, tag = NULL) {
    assert_string(quick, allow_empty = FALSE, allow_null = TRUE)
    if (!is.null(mode)) {
        mode <- rlang::arg_match0(mode, c(
            "titleCreatorYear", "everything",
            "contains", "startsWith"
        ))
    }
    if (!is.null(tag)) {
        tag <- as.character(tag)
        if (anyNA(tag)) {
            cli::cli_abort("{.arg tag} cannot contain missing value.")
        }
    }
    structure(
        list(quick = quick, mode = mode, tag = tag),
        class = "param_search"
    )
}

#' @export
merge.param_search <- function(x, y, ...) {
    y <- y[!vapply(y, is.null, logical(1L), USE.NAMES = FALSE)]
    modify_list(x, y)
}

#' @export
query_params.param_search <- function(params, ..., mode) {
    query <- list()
    if (!is.null(params$quick)) query$q <- params$quick
    query$qmode <- params$mode %||% mode
    if (!is.null(tag <- params$tag)) {
        names(tag) <- rep_len("tag", length(tag))
        query <- c(query, tag)
    }
    query
}
