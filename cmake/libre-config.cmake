if("@LIBRE_BUILD_STATIC@")
    include(CMakeFindDependencyMacro)
    find_dependency(Threads)
    if("@USE_OPENSSL@")
        find_dependency(OpenSSL)
    endif()
    if("@ZLIB_FOUND@")
        find_dependency(ZLIB)
    endif()
endif()

include("${CMAKE_CURRENT_LIST_DIR}/libre-targets.cmake")

# convenience target libre::libre for uniform usage
if(NOT TARGET libre::libre)
    if(TARGET libre::re_shared AND (BUILD_SHARED_LIBS OR NOT TARGET libre::re))
        add_library(libre::libre INTERFACE IMPORTED)
        set_target_properties(libre::libre PROPERTIES INTERFACE_LINK_LIBRARIES libre::re_shared)
    elseif(TARGET libre::re AND (NOT BUILD_SHARED_LIBS OR NOT TARGET libre::re_shared))
        add_library(libre::libre INTERFACE IMPORTED)
        set_target_properties(libre::libre PROPERTIES INTERFACE_LINK_LIBRARIES libre::re_shared)
    endif()
endif()
