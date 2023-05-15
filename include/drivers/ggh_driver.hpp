#pragma once

#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>
#include <tuple>

#include <crypto++/cryptlib.h>
#include <crypto++/osrng.h>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/util.hpp"
#include "../Eigen/Dense"

using namespace Eigen;

#define GGH_N 16
#define GGH_D 200
#define GGH_DELTA 21

typedef Matrix<long double, Eigen::Dynamic, Eigen::Dynamic> Mat;

class GGHDriver {
public:
  Mat gen_U();
  Mat gen_V();
  std::pair<Mat, Mat> GGH_generate();
  Mat GGH_encrypt(Mat pk, Mat m, std::optional<Mat> rand);
  Mat GGH_decrypt(Mat sk, Mat pk, Mat e);
  Mat byteblock_to_ggh(CryptoPP::SecByteBlock block);
  CryptoPP::SecByteBlock ggh_to_byteblock(Mat m, size_t nbytes);
  Mat gen_random(int rows, int cols, int range);
  Mat babai(Mat w, Mat V);
  double hadamard_ratio(Mat M);
};

void eigentest();