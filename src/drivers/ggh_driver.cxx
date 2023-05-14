#include "../../include/drivers/ggh_driver.hpp"

using namespace Eigen;

MatrixXd gen_U() {
  CryptoPP::AutoSeededRandomPool rng;
  MatrixXd U = MatrixXd::Identity(GGH_N, GGH_N);
  for (int i = 0; i < GGH_N; i++) {
    CryptoPP::Integer swap(rng, 0, (GGH_N-1)*2);
    long swap_l = swap.ConvertToLong();
    long j = swap_l % (GGH_N-1);
    MatrixXd tmp = U.row(i);
    U.row(i) = U.row(j);
    U.row(j) = tmp;
    if (j != swap_l) {
        U.row(i) *= -1;
    }
  }
  return U;
}

void eigentest() {
  MatrixXd m = gen_U();
  std::cout << m << std::endl;
  std::cout << m.determinant() << std::endl;
}