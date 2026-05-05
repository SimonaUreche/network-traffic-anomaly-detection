#pragma once
#include <stdio.h>
#include "flow_table.h"

//deschidem fisierul csv si scrie headerul
FILE *csv_writer_open(const char *filename);
void csv_writer_write(FILE *file, const FlowStats *flow);
void csv_writer_close(FILE *file);
