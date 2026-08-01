cmake_minimum_required(VERSION 3.18)
project(datachannel-consumer C)

find_package(libre CONFIG REQUIRED)

add_executable(datachannel-consumer main.c)
target_link_libraries(datachannel-consumer PRIVATE libre::datachannel)
