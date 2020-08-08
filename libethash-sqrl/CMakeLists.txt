file(GLOB sources "*.cpp")
file(GLOB headers "*.h")

add_library(ethash-sqrl ${sources} ${headers})
#target_link_libraries(ethash-sqrl ethcore ethash::ethash Boost::fiber Boost::thread)
target_link_libraries(ethash-sqrl ethcore ethash::ethash Boost::thread)
target_include_directories(ethash-sqrl PRIVATE .. ${CMAKE_CURRENT_BINARY_DIR})
