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
class HTMChecker : public Checker<check::PreCall> {
  const CallDescription BeginFn{CDM::SimpleFunc, {"nstm_begin"}, 0};
  const CallDescription EndFn{CDM::SimpleFunc, {"nstm_end"}, 0};

  const BugType DoubleBeginBugType{this, "Double begin"};

  void reportDoubleBegin(const CallEvent &Call, CheckerContext &C) const;

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

REGISTER_TRAIT_WITH_PROGRAMSTATE(InTransactionState, bool);

void HTMChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (BeginFn.matches(Call)) {
    ProgramStateRef State = C.getState();
    bool inTransaction = State->get<InTransactionState>();
    if (inTransaction) {
      reportDoubleBegin(Call, C);
      return;
    }

    State = State->set<InTransactionState>(true);
    C.addTransition(State);

  } else if (EndFn.matches(Call)) {
    ProgramStateRef State = C.getState();

    State = State->set<InTransactionState>(false);
    C.addTransition(State);
  }
}

void HTMChecker::reportDoubleBegin(const CallEvent &Call,
                                   CheckerContext &C) const {
  // We reached a bug, stop exploring the path here by generating a sink.
  ExplodedNode *ErrNode = C.generateErrorNode();
  // If we've already reached this node on another path, return.
  if (!ErrNode)
    return;

  // Generate the report.
  auto R = std::make_unique<PathSensitiveBugReport>(
      DoubleBeginBugType,
      "Trying to start a transaction while inside a transaction (target "
      "implementation does not support nesting)",
      ErrNode);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void ento::registerHTMChecker(CheckerManager &mgr) {
  mgr.registerChecker<HTMChecker>();
}

// This checker should be enabled regardless of how language options are set.
bool ento::shouldRegisterHTMChecker(const CheckerManager &mgr) { return true; }
