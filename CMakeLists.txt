cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

if(APPLE)
     if(NOT CMAKE_OSX_DEPLOYMENT_TARGET)
        set(CMAKE_OSX_DEPLOYMENT_TARGET "10.12" CACHE STRING "" FORCE)
    endif()
endif()

project(zhikan-gui
    VERSION 1.6.2
    HOMEPAGE_URL https://www.5151ml.com/
    LANGUAGES CXX
)

message(STATUS "Building ${PROJECT_NAME} v${PROJECT_VERSION} [cmake]")

# The SHORT and COMPANY names affect the installation directory.
set(PRODUCT_NAME_SHORT "ZKVPN")
set(PRODUCT_NAME_COMPANY "智瞰数科团队")
set(PRODUCT_NAME_COMPANY_DOMAIN "www.5151ml.com")
set(INTERNAL_PROJECT_VERSION "${PROJECT_VERSION}")

# The long name is used as the installer description
# and About screen description.
set(PRODUCT_NAME_LONG "智瞰VPN客户端")

# Printed in the About screen
set(PRODUCT_NAME_COPYRIGHT_SHORT "Copyright © 2016-2026 Zhikanshuke Inc., Zhikanshuke")
set(PRODUCT_NAME_COPYRIGHT_FULL "Copyright © 2014-2026 Zhikanshuke Inc.")

# The application name / main window title / installer app name
set(APP_NAME "ZKVPN")
# The URL for determining the latest release
set(GITLAB_LATEST_RELEASE_URL "https://www.5151ml.com/")
# The URL for the latest release
set(APP_RELEASES_URL "https://www.5151ml.com/")
# The URL for downloading the latest release
set(APP_DOWNLOAD_WIN_URL "https://www.5151ml.com/")

set(APP_ISSUES_URL "https://www.5151ml.com/")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/CMake/Modules/")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/CMake/Includes/")

set(SIGN_EXE "false" CACHE STRING "When set to true the executable will be signed")

include(ProjectSettings)
include(ProjectDependencies)

if(MINGW)
    # FIXME: upgrading CMake from 3.15 to newer version fails on packaging
    # because objdump.exe is not supported (actually the exe suffix break it)
    # TODO: bundling dependencies use CMake deprecated function; need update..
    find_program(CMAKE_OBJDUMP NAMES objdump.exe)
    string(REGEX REPLACE "\\.exe$" "" CMAKE_OBJDUMP ${CMAKE_OBJDUMP})

endif()

add_subdirectory(src)

install(FILES LICENSE.txt
    DESTINATION .
    COMPONENT App
)

include(clang-format)
include(git_revision_main)
include(build_timestamp_main)

include(ProjectPackage)

