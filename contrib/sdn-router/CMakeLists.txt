check_include_file_cxx(ns3/ofswitch13-device.h HAVE_OFSWITCH13)

if(NOT HAVE_OFSWITCH13 AND NOT DEFINED libofswitch13)
    message(${HIGHLIGHTED_STATUS} "Skipping contrib/sdn-router (missing ofswitch13 dependency)")
    return()
endif()

add_definitions(-DHAVE_STRLCPY=1)

set(source_files
    model/sdn-router-switch.cc
    model/sdn-router-controller.cc
)

set(header_files
    model/sdn-router-switch.h
    model/sdn-router-controller.h
)

build_lib(
    LIBNAME sdn-router
    SOURCE_FILES ${source_files}
    HEADER_FILES ${header_files}
    LIBRARIES_TO_LINK ${libcore} ${libnetwork} ${libinternet} ${libofswitch13}
    TEST_SOURCES test/sdn-router-test-suite.cc
)
