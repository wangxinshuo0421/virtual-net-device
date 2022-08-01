#include <stdio.h>
int main(int argc, char const *argv[])
{
    char msg[1000];
    for(int i = 0; i < 1000; i++)
        msg[i] = 'a';
    msg[9] = '\0';
    printf("ans:%s", msg);
    return 0;
}
