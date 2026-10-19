/* The few math routines the program uses, for a freestanding build.
 * Precision is the game's need, not IEEE's: these feed configuration
 * values and the odd scale factor, never the fixed-point renderer. */
#include <math.h>

double sqrt(double x)
{
    return __builtin_sqrt(x);    /* one FSQRT instruction */
}

double floor(double x)
{
    long i = (long)x;

    return (double)(x < (double)i ? i - 1 : i);
}

double ceil(double x)
{
    long i = (long)x;

    return (double)(x > (double)i ? i + 1 : i);
}

double pow(double x, double y)
{
    long n = (long)y;
    double r = 1;

    if ((double)n != y)
        return 0;               /* only integral powers are ever asked */
    for (long k = n < 0 ? -n : n; k; k--)
        r *= x;
    return n < 0 ? 1 / r : r;
}

double sin(double x)
{
    /* Range-reduced Taylor series; adequate for the rare caller. */
    const double pi = 3.14159265358979323846;
    double t, r;

    while (x > pi)
        x -= 2 * pi;
    while (x < -pi)
        x += 2 * pi;
    t = x;
    r = x;
    for (int k = 1; k < 10; k++) {
        t *= -x * x / ((2 * k) * (2 * k + 1));
        r += t;
    }
    return r;
}

double cos(double x)
{
    return sin(x + 1.57079632679489661923);
}

double tan(double x)
{
    return sin(x) / cos(x);
}

double atan(double x)
{
    /* atan via the series around 0 after reducing |x| <= 1. */
    const double half_pi = 1.57079632679489661923;
    double r, t, x2;
    int invert = 0;

    if (x > 1 || x < -1) {
        invert = 1;
        x = 1 / x;
    }
    x2 = x * x;
    t = x;
    r = x;
    for (int k = 1; k < 40; k++) {
        t *= -x2;
        r += t / (2 * k + 1);
    }
    if (invert)
        r = (x > 0 ? half_pi : -half_pi) - r;
    return r;
}
