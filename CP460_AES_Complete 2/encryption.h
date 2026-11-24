#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>
#include <vector>

std::vector<unsigned char> encryptAES(const std::string& message,
                                      const std::vector<unsigned char>& key,
                                      const std::vector<unsigned char>& iv);

std::string toHex(const std::vector<unsigned char>& data);

#endif
