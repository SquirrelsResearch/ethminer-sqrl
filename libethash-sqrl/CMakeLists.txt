file(GLOB sources CONFIGURE_DEPENDS "*.cpp")
file(GLOB csources CONFIGURE_DEPENDS "*.c")
file(GLOB headers CONFIGURE_DEPENDS "*.h")

add_library(ethash-sqrl ${csources} ${sources} ${headers})
#target_link_libraries(ethash-sqrl ethcore ethash::ethash Boost::fiber Boost::thread)
target_link_libraries(ethash-sqrl ethcore ethash::ethash Boost::thread)
target_include_directories(ethash-sqrl PRIVATE .. ${CMAKE_CURRENT_BINARY_DIR})
