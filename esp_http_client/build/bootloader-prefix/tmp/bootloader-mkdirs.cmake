# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "C:/Users/ismae/esp1/components/bootloader/subproject"
  "C:/Users/ismae/Desktop/Esp32cliente/esp_http_client/build/bootloader"
  "C:/Users/ismae/Desktop/Esp32cliente/esp_http_client/build/bootloader-prefix"
  "C:/Users/ismae/Desktop/Esp32cliente/esp_http_client/build/bootloader-prefix/tmp"
  "C:/Users/ismae/Desktop/Esp32cliente/esp_http_client/build/bootloader-prefix/src/bootloader-stamp"
  "C:/Users/ismae/Desktop/Esp32cliente/esp_http_client/build/bootloader-prefix/src"
  "C:/Users/ismae/Desktop/Esp32cliente/esp_http_client/build/bootloader-prefix/src/bootloader-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "C:/Users/ismae/Desktop/Esp32cliente/esp_http_client/build/bootloader-prefix/src/bootloader-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "C:/Users/ismae/Desktop/Esp32cliente/esp_http_client/build/bootloader-prefix/src/bootloader-stamp${cfgdir}") # cfgdir has leading slash
endif()
