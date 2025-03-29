#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include <utility>

using namespace clang;
using namespace ento;

namespace {
class HTMChecker : public Checker<check::PostCall> {
public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

REGISTER_TRAIT_WITH_PROGRAMSTATE(InTransaction, bool);

void HTMChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {

}

void ento::registerHTMChecker(CheckerManager &mgr) {
  mgr.registerChecker<HTMChecker>();
}

// This checker should be enabled regardless of how language options are set.
bool ento::shouldRegisterHTMChecker(const CheckerManager &mgr) { return true; }
