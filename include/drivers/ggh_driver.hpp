#pragma once

#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>
#include <tuple>

#include <crypto++/cryptlib.h>
#include <crypto++/osrng.h>

#include "../../include-shared/constants.hpp"
#include "../Eigen/Dense"

using namespace Eigen;

MatrixXd gen_U();
void eigentest();