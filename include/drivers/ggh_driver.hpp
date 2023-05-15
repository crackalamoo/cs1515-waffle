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

typedef Matrix<long double, Eigen::Dynamic, Eigen::Dynamic> Mat;

class GGHDriver {
public:
  Mat gen_U();
  Mat gen_V();
  std::pair<Mat, Mat> GGH_generate();
  Mat GGH_encrypt(Mat pk, Mat m, std::optional<Mat> rand);
  Mat GGH_decrypt(Mat sk, Mat pk, Mat e);
  Mat gen_random(int rows, int cols, int range);
  Mat babai(Mat w, Mat V);
  double hadamard_ratio(Mat M);
};

void eigentest();