#include <algorithm>
#include <cstring>
#include <bitset>
#include <vector>
#include <tuple>
#include <cassert>
#include <cstdint>
//constexpr size_t N_MONO = 1 + 256 + 256 * 255 / 2;
//using deg2_rel = std::bitset<1 + 256 + 256 * 255 / 2>;
//using deg2_rel64 = std::bitset<1 + 64 + 64 * 63 / 2>;
using lin_rel = std::bitset<256>;
struct sym_u64
{
	lin_rel st[64] {};
	sym_u64& operator^=(const sym_u64& rhs)
	{
		for(size_t i = 0; i < 64; i++)
			st[i] ^= rhs.st[i];
		return *this;
	}
	sym_u64 operator^(const sym_u64& rhs) const
	{
		sym_u64 ret = *this;
		ret ^= rhs;
		return ret;
	}
	sym_u64 operator<<(int by) const
	{
		sym_u64 ret {};
		for(size_t i = 0; i < 64 - by; i++)
			ret.st[i + by] = st[i];
		return ret;
	}
	sym_u64 operator>>(int by) const
	{
		sym_u64 ret {};
		for(size_t i = 0; i < 64 - by; i++)
			ret.st[i] = st[i + by];
		return ret;
	}
	sym_u64 rotl(int by) const
	{
		sym_u64 ret {};
		for(size_t i = 0; i < 64; i++)
			ret.st[(i + by)%64] = st[i];
		return ret;
	}
};
struct sym_xs256
{
	sym_u64 s0 {}, s1 {}, s2 {}, s3 {};
	sym_xs256()
	{
		for(size_t i = 0; i < 64; i++)
		{
			s0.st[i][i] = true;
			s1.st[i][i+64] = true;
			s2.st[i][i+128] = true;
			s3.st[i][i+192] = true;
		}
	}
	std::pair<sym_u64, sym_u64> step()
	{
		sym_u64 res_s0 = s0;
		sym_u64 res_s3 = s3;
		sym_u64 t = s1 << 17;
		s2 ^= s0;
		s3 ^= s1;
		s1 ^= s2;
		s0 ^= s3;
		s2 ^= t;
		s3 = s3.rotl(45);
		return {res_s0, res_s3};
	}
};
uint64_t rotl(uint64_t a, int b) { return (a << b) | (a >> (64 - b)); }
int unhex(char c)
{
	if('0' <= c && c <= '9')
		return c - '0';
	if('a' <= c && c <= 'f')
		return c - 'a' + 10;
	assert(false);
}
void unhex(uint8_t* buf, char* src, size_t n)
{
	for(size_t i = 0; i < n; i++)
		buf[i] = unhex(src[2*i])*16 + unhex(src[2*i+1]);
}
int dist(int a, int b)
{
	return std::min((a-b+16777216)%16777216, (b-a+16777216)%16777216);
}
lin_rel mask(std::pair<sym_u64, sym_u64> out, int i)
{
	auto ret = out.first.st[0] ^ out.first.st[23] ^ out.second.st[0];
	if(i == 1)
		ret ^= out.first.st[22];
	return ret;
}
int main()
{
	sym_xs256 rng {};
	//constexpr size_t N = 50000;
	constexpr size_t N = 1500;
	//constexpr size_t N = 1000;
	std::vector<std::pair<sym_u64, sym_u64>> outs;
	for(size_t i = 0; i < 6*N; i++)
		outs.push_back(rng.step());
	//printf("Done outs\n");
	std::vector<std::vector<uint8_t>> inp;
	for(size_t i = 0; i < N; i++)
	{
		char line[256]{};
		scanf("%s", line);
		uint8_t unh[41];
		unhex(unh, line, 41);
		inp.push_back(std::vector<uint8_t>(unh, unh+41));
		//printf("%d %d\n", unh[0], unh[40]);
	}
	using match = std::tuple<int, int, int, int>;
	std::vector<match> matches;
	for(size_t i = 0; i < N; i++)
	{
		int val = uint8_t(inp[i][0] ^ 'b') + 256*uint8_t(inp[i][1] ^ 'r') + 65536*uint8_t(inp[i][2] ^ 'i');
		matches.push_back({dist(val,   0*65536), 6*i, 0, 1});
		matches.push_back({dist(val, 128*65536), 6*i, 0, 0});
		matches.push_back({dist(val,  64*65536), 6*i, 1, 0});
		matches.push_back({dist(val, 192*65536), 6*i, 1, 1});
	}
	std::sort(matches.begin(), matches.end());
	FILE* file = fopen("mat", "w");
	for(size_t mi = 0; mi < 400; mi++)
	{
		auto[d, i, ind, val] = matches[mi];
		//printf("%lf\n", d / 16777216.0);
		lin_rel L = mask(outs[i], ind);
		uint8_t R = val;
		fprintf(file, "%s %d\n", L.to_string().data(), R);
	}
	fclose(file);
	system("python3 3.py mat > sol");
	char sol[300];
	file = fopen("sol", "r");
	fscanf(file, "%299s", sol);
	fclose(file);
	rng = {};
	lin_rel ist(sol);
	char ans[41]{};
	for(size_t i = 0; i < 5; i++)
	{
		uint64_t x = 0, y = 0;
		auto[s1, s2] = rng.step();
		for(size_t j = 0; j < 64; j++)
		{
			x |= uint64_t((ist & s1.st[j]).count() % 2) << j;
			y |= uint64_t((ist & s2.st[j]).count() % 2) << j;
		}
		uint64_t z = rotl(x + y, 23) + x;
		uint64_t w;
		memcpy(&w, inp[0].data() + 8*i, 8);
		w ^= z;
		memcpy(ans + 8*i, &w, 8);
	}
	printf("%s\n", ans);
}
