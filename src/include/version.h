
#if !defined(_LRD_VERSION_STRING)
	#error "error: undefined development version - please define via build system"
#endif

#define LRD_BUILD_NUMBER "7.0.0.624"

#ifndef LAIRD_SDK_MSB
#error "error: API version defines not present"
#endif

//the component value should not change
#define LAIRD_COMPONENT    92

// the following #DEFINES should not be modified by hand
// -----------------------------------------------------
#define STR_VALUE(arg) #arg
#define ZVER(name) STR_VALUE(name)

#define DCAL_VERSION_STR ZVER(LAIRD_SDK_MSB) "." ZVER(LAIRD_DCAL_MAJOR) "." ZVER(LAIRD_DCAL_MINOR)
#define DCAL_VERSION ((LAIRD_SDK_MSB << 16) | (LAIRD_DCAL_MAJOR << 8) | LAIRD_DCAL_MINOR)
#define DCAS_COMPONENT_VERSION ((LAIRD_COMPONENT << 24) | (LAIRD_SDK_MSB << 16) | (LAIRD_DCAL_MAJOR << 8) | LAIRD_DCAL_MINOR)
// -----------------------------------------------------
