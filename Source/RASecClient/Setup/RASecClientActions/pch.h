#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers

#pragma comment(lib, "msi.lib")

#include <stdio.h>
#include <stdarg.h>

#include <windows.h>
#include <shellapi.h>
#include <msi.h>
#include <msiquery.h>
#include <msidefs.h>

#include <RASecCore/CommonClient.h>
#pragma comment(lib, "RASecCore")
