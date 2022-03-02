获取cpu个数

cpu_core_count = sysconf(_SC_NPROCESSORS_ONLN);

获取逻辑cpu个数



     FILE* f = fopen("/proc/stat", "r");
      u8 tmp[1024];
      u32 val = 0;
    
      if (!f) return 0;
    
      while (fgets(tmp, sizeof(tmp), f)) {
    if (!strncmp(tmp, "procs_running ", 14) ||
        !strncmp(tmp, "procs_blocked ", 14)) 
        val += atoi(tmp + 14); 
        }

