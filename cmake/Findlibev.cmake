find_path(
    LIBEV_INCLUDE_DIR
    NAMES ev.h
    PATHS
        /usr/include
        /usr/local/include
        /opt/homebrew/include
        /ucrt64/include
        ENV CPATH
)

find_library(
    LIBEV_LIBRARY
    NAMES ev
    PATHS
        /usr/lib
        /usr/local/lib
        /opt/homebrew/lib
        /ucrt64/lib
        ENV LIBRARY_PATH
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    libev DEFAULT_MSG LIBEV_LIBRARY LIBEV_INCLUDE_DIR
)

if (LIBEV_FOUND)
    set(LIBEV_LIBRARIES ${LIBEV_LIBRARY})
    set(LIBEV_INCLUDE_DIRS ${LIBEV_INCLUDE_DIR})

    if (NOT TARGET libev)
        add_library(libev UNKNOWN IMPORTED)
        set_target_properties(libev PROPERTIES
            IMPORTED_LOCATION "${LIBEV_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${LIBEV_INCLUDE_DIR}"
        )
    endif()
endif()
