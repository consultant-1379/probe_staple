#include "PageViewPrinter.h"
#include "PageViewPrinterTab.h"
#include "Resource.h"

PageViewPrinterText::PageViewPrinterText(std::ostream& o) : PageViewPrinter(), out_(o)
{ }

void PageViewPrinterText::printPageView(const Resource* r)
{
	r->printSummary(out_);
}

void PageViewPrinterText::printLonelyResource(const Resource* r)
{
	r->printSummary(out_);
}

void PageViewPrinterText::close()
{ }
