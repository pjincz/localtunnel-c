find_path(LIBEV_INCLUDE_DIR NAMES ev.h PATHS @PACKAGE_INCLUDE_INSTALL_DIR@)

find_library(LIBEV_LIBRARY NAMES ev PATHS @PACKAGE_LIB_INSTALL_DIR@)

if (LIBEV_INCLUDE_DIR AND LIBEV_LIBRARY)
    set(LIBEV_FOUND TRUE)
    set(LIBEV_LIBRARIES ${LIBEV_LIBRARY})
    set(LIBEV_INCLUDE_DIRS ${LIBEV_INCLUDE_DIR})

    if (NOT TARGET libev)
        add_library(libev UNKNOWN IMPORTED)
        set_target_properties(libev PROPERTIES
            IMPORTED_LOCATION "${LIBEV_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${LIBEV_INCLUDE_DIR}"
        )
    endif()
else()
    set(LIBEV_FOUND FALSE)
    message(FATAL_ERROR "libev not found")
endif()
