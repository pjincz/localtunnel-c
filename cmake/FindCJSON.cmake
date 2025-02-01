find_path(
    CJSON_INCLUDE_DIR
    NAMES cjson/cJSON.h
    PATHS
        /usr/include
        /usr/local/include
        /opt/homebrew/include
        /ucrt64/include
        ENV CPATH
)

find_library(
    CJSON_LIBRARY
    NAMES cjson
    PATHS
        /usr/lib
        /usr/local/lib
        /opt/homebrew/lib
        /ucrt64/lib
        ENV LIBRARY_PATH
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    CJSON DEFAULT_MSG CJSON_LIBRARY CJSON_INCLUDE_DIR
)

if (CJSON_FOUND)
    set(CJSON_LIBRARIES ${CJSON_LIBRARY})
    set(CJSON_INCLUDE_DIRS ${CJSON_INCLUDE_DIR})

    if (NOT TARGET cJSON)
        add_library(cJSON UNKNOWN IMPORTED)
        set_target_properties(cJSON PROPERTIES
            IMPORTED_LOCATION "${CJSON_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${CJSON_INCLUDE_DIR}"
        )
    endif()
endif()
