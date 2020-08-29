file(GLOB CONFIGURE_DEPENDS sources "*.cpp")
file(GLOB CONFIGURE_DEPENDS csources "*.c")
file(GLOB CONFIGURE_DEPENDS headers "*.h")

add_library(ethash-sqrl ${csources} ${sources} ${headers})
#target_link_libraries(ethash-sqrl ethcore ethash::ethash Boost::fiber Boost::thread)
target_link_libraries(ethash-sqrl ethcore ethash::ethash Boost::thread)
target_include_directories(ethash-sqrl PRIVATE .. ${CMAKE_CURRENT_BINARY_DIR})
