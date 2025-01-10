/*****************************************************************//**
 * \file   memxx_supplement.c
 * \brief  内存(memory)操作函数的补充
 * \brief  注意标准库中string.h中的memxxx相关函数也不以'\0'为结束。
 * \brief  或者说u8数组的一些操作
 *
 * \author CaiYunWei
 * \date   August 2024
 *********************************************************************/

#include "memxx_supplement.h"


void memPrint(const void* target, size_t number)
{
	for (uint8_t* p = (uint8_t*)target; p < (uint8_t*)target + number; p++)
	{
		printf("%02X ", *p);
	}
	putchar('\n');
}




void memReversalV1(const void* start, const void* end)
{
	uint8_t* pFront = (uint8_t*)start;
	uint8_t* pBack = (uint8_t*)end;
	uint8_t tem;
	while (pFront < pBack)
	{
		tem = *pFront;
		*pFront = *pBack;
		*pBack = tem;

		pFront++;
		pBack--;
	}
}


void memReversalV2(const void* start, size_t number)
{
	uint8_t* pFront = (uint8_t*)start;
	uint8_t* pBack = pFront + number - 1;
	memReversalV1(pFront, pBack);
}


void* memMathingNative(const void* major, size_t num1, const void* target, size_t num2)
{
	uint8_t* const end1 = (uint8_t*)major + num1 - 1;//得到major中的结束位置
	uint8_t* const start2 = (uint8_t*)target;//记录模式数组初始位置
	uint8_t* const end2 = (uint8_t*)target + num2 - 1;//得到target中的结束位置

	uint8_t* it = (uint8_t*)major;//某次开始比较的位置
	uint8_t* it1 = it;//主数组遍历用的指针
	uint8_t* it2 = start2;//模式数组遍历用的指针

	while ((it1 <= end1) && (it2 <= end2))
	{
		if (*it1 == *it2)
		{
			it1++;
			it2++;
		}
		else//某次匹配失败，则看下一个子数组
		{
			it++;//下一个
			it1 = it;//回溯至“下一个”的开头
			it2 = start2;//回溯至模式数组开头
		}
	}

	//模式数组中能都比完(此时 it2 为 end2 + 1)，说明找到了
	if (it2 > end2)
		return (void*)it;
	else
		return NULL;
}



/**
 * 求nextval数组.
 *
 * \param theStart 模式数组
 * \param number 模式数组长度
 * \return 求得的next数组地址
 * \return NULL 传入了空字符串或内存申请失败
 */
size_t* memGetNextval(const void* target, size_t number)
{

	//不应当传入空字符串
	if (number < 1) return NULL;

	size_t* next = (size_t*)malloc(number * sizeof(size_t));
	if (next == NULL) return NULL;

	next[0] = 0;
	if (number < 2) return next;

	next[1] = 0;

	uint8_t* const theStart = (uint8_t*)target;
	uint8_t* const theEnd = theStart + number - 1;//最后一个非'\0'字符

	uint8_t* it = theStart + 1;//正在比较的子串
	uint8_t* it1 = it;//主串遍历用
	uint8_t* it2 = theStart;//字串遍历用
	//递推，j=1的已知知道j=2，故初始it为target + 1，it2为target


	while (it1 != theEnd)
	{
		size_t j = it1 - theStart;
		size_t k = it2 - theStart;
		if (*it1 == *it2)
		{
			next[j + 1] = k + 1;
			if (theStart[j + 1] == theStart[k + 1])//优化
				next[j + 1] = next[k + 1];
			it1++;
			it2++;
		}
		else
		{
			if (k == 0)//根本没有出现部分匹配，特殊不匹配情况
			{
				next[j + 1] = 0;
				it++;//看下一子串
				it1++;//看下一子串

			}
			else//有部分匹配，（一般不匹配情况）
			{
				it2 = theStart + next[k];//it2跳转，“滑动”
				it = it1 - next[k];//记录位置
			}
		}
	}

	return next;
}


void* memMathingKMP(const void* major, size_t num1, const void* target, size_t num2)
{
	uint8_t* const end1 = (uint8_t*)major + num1 - 1;//得到主数组中的结束位置
	uint8_t* const start2 = (uint8_t*)target;//记录模式数组初始位置
	uint8_t* const end2 = (uint8_t*)target + num2 - 1;//得到模式数组中的结束位置

	size_t* next = memGetNextval(target, num2);//得到next数组

	if (next == NULL)
		return NULL;

	uint8_t* it = (uint8_t*)major;//“正在”匹配的子串
	uint8_t* it1 = it;//主串遍历用
	uint8_t* it2 = start2;//字串遍历用

	while ((it1 <= end1) && (it2 <= end2))
	{
		if (*it1 == *it2)
		{
			it1++;
			it2++;
		}
		else
		{
			if (it2 == start2)//根本没有出现部分匹配，特殊不匹配情况
			{
				it++;//看下一子串
				it1 = it;//看下一子串
			}
			else//有部分匹配（一般不匹配情况）
			{
				//得到不匹配的元素编号，用it1 - it 也行
				size_t j = it2 - start2;

				it += j - next[j];//“滑动”，记录位置，用 it = it1 - next[j];也行
				it2 = start2 + next[j];//it2跳转
			}
		}
	}

	free(next);

	if (it2 > end2)
	{
		return (void*)it;
	}
	else
		return NULL;
}


