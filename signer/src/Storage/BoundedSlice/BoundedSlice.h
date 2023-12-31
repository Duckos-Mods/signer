#pragma once
#include <memory>
#include <stdexcept>
#include <vector>


/*
* A Utility class that allows me to take an array. Pick two indexes then treat them as a new array with out copying the data.
*/
template <typename sliceType>
class BoundedSlice
{
private:
	std::vector<sliceType> m_fullObject;
	size_t m_start;
	size_t m_end;
	size_t m_size;

	size_t m_cstyleMaxSize = 0;

public:
	BoundedSlice(const std::vector<sliceType>& fullObject, size_t start, size_t end, size_t cstyleMaxSize)
		: m_fullObject(fullObject),
		m_start(start),
		m_end(end),
		m_size(end - start),
		m_cstyleMaxSize(cstyleMaxSize)
	{}
	BoundedSlice() : m_fullObject(nullptr), m_start(0), m_end(0), m_size(0) {}
	inline size_t size() { return m_size; }
	inline sliceType& operator[](size_t index) {
		sliceType temp = m_fullObject[m_start + index];
		return temp;
	}
	inline const sliceType& operator[](size_t index) const {
		sliceType temp = m_fullObject[m_start + index];
		return temp;
	}
	inline sliceType& at(size_t index) {
		// Bounds check
		if (index + m_start >= m_cstyleMaxSize) {
			throw std::out_of_range("Index out of range");
		}

		return m_fullObject[m_start + index];
	}

	inline sliceType atClone(size_t index) {
		return m_fullObject[m_start + index];
	}


	inline sliceType& front() { return m_fullObject[m_start]; }
	inline sliceType& back() { return m_fullObject[m_end]; }
	inline sliceType* data() { return &m_fullObject[m_start]; }
	// Itter support
	inline sliceType* begin() { return &m_fullObject[m_start]; }
	inline sliceType* end() { return &m_fullObject[m_end]; }

	// Setters
	inline void setStart(size_t start) { m_start = start; }
	inline void setEnd(size_t end) { m_end = end; }
	inline void setFullObject(sliceType* fullObject) { m_fullObject = fullObject; }

	// This function 
	inline void slide(size_t ammount) { m_start += ammount; m_end += ammount; }

	// Getters
	inline size_t getStart() { return m_start; }
	inline size_t getEnd() { return m_end; }


};

