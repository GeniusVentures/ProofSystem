cmake_minimum_required(VERSION 3.22)

project(ProofSystem LANGUAGES C CXX)

add_subdirectory(src)

install(
    TARGETS KeyGeneration
    EXPORT ${PROJECT_NAME}Config
    PUBLIC_HEADER
)

install(
    EXPORT ${PROJECT_NAME}Config
    NAMESPACE sgns::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)
