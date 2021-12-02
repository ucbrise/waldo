#pragma once

#define INIT_TIMER auto start_timer = std::chrono::high_resolution_clock::now(); \
    uint64_t pause_timer = 0;
#define START_TIMER  start_timer = std::chrono::high_resolution_clock::now();
#define PAUSE_TIMER(name) pause_timer += std::chrono::duration_cast<std::chrono::milliseconds>( \
            std::chrono::high_resolution_clock::now()-start_timer).count(); \
    std::cout << "[PAUSING TIMER] RUNTIME till now of " << name << ": " << pause_timer<<" millisec"<<std::endl;
#define STOP_TIMER(name) std::cout << "------------------------------------" << std::endl; std::cout << "[STOPPING TIMER] Total RUNTIME of " << name << ": " << \
    std::chrono::duration_cast<std::chrono::milliseconds>( \
            std::chrono::high_resolution_clock::now()-start_timer \
    ).count() + pause_timer << " millisec " << std::endl; 
#define STOP_TIMER_() std::chrono::duration_cast<std::chrono::milliseconds>( \
            std::chrono::high_resolution_clock::now()-start_timer \
    ).count() + pause_timer
#define TIMER_TILL_NOW std::chrono::duration_cast<std::chrono::milliseconds>(\
    std::chrono::high_resolution_clock::now()-start_timer).count()

