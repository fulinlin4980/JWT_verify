﻿cmake_minimum_required(VERSION 3.10)

project(SJwt VERSION 1.0 LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)
#set(CMAKE_AUTOUIC ON)
#set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 COMPONENTS REQUIRED Core)

file(GLOB SJWT_CPP "${CMAKE_CURRENT_LIST_DIR}/*.cpp")
file(GLOB SJWT_H "${CMAKE_CURRENT_LIST_DIR}/*.h")

list(APPEND SRC_FILES ${SJWT_CPP} ${SJWT_H})

add_library(${PROJECT_NAME} STATIC ${SRC_FILES} )

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/)

target_link_libraries(${PROJECT_NAME} PUBLIC Qt6::Core)