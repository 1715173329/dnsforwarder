#include <stdio.h>
#include <time.h>
#include "../../timedtask.h"

void p(const char *t, void *u)
{
    printf("%lu : %s\n", time(NULL), t);
}

int main(void)
{
    TimeTask_Init();

    printf("-->Job 1, Executing every 2 seconds.\n");
    TimeTask_Add(FALSE, 2000, p, "Job 1 .", NULL);

    printf("-->Job 2, Executing every 3 seconds.\n");
    TimeTask_Add(FALSE, 3000, p, "Job 2 .", NULL);

    SLEEP(10000);

    printf("-->Job 3, Executing after 5 seconds.\n");
    TimeTask_Add(FALSE, 5000, p, "Job 3 .", NULL);

    SLEEP(9999999);
    return 0;
}
