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
  const BugType UnmatchedEnd{this, "Unmatched end"};

  void reportDoubleBegin(const CallEvent &Call, CheckerContext &C) const;

  void reportUnmatchedEnd(const CallEvent &Call, CheckerContext &C) const;

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

REGISTER_TRAIT_WITH_PROGRAMSTATE(InTransactionState, bool);

void HTMChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const bool inTransaction = State->get<InTransactionState>();
  const bool isBegin = BeginFn.matches(Call);
  const bool isEnd = EndFn.matches(Call);

  assert(!(isBegin && isEnd));

  if (isBegin && inTransaction) {
    reportDoubleBegin(Call, C);
    return;
  }

  if (isEnd && !inTransaction) {
    reportUnmatchedEnd(Call, C);
    return;
  }

  State = State->set<InTransactionState>(isBegin);
  C.addTransition(State);
}

void HTMChecker::reportDoubleBegin(const CallEvent &Call,
                                   CheckerContext &C) const {
  ExplodedNode *ErrNode = C.generateErrorNode();
  if (!ErrNode)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      DoubleBeginBugType,
      "Trying to start a transaction while inside a transaction (target "
      "implementation does not support nesting)",
      ErrNode);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void HTMChecker::reportUnmatchedEnd(const CallEvent &Call,
                                 CheckerContext &C) const {
  ExplodedNode *ErrNode = C.generateErrorNode();
  if (!ErrNode)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(
      UnmatchedEnd,
      "Trying to end a transaction while outside a transaction", ErrNode);
  R->addRange(Call.getSourceRange());
  C.emitReport(std::move(R));
}

void ento::registerHTMChecker(CheckerManager &mgr) {
  mgr.registerChecker<HTMChecker>();
}

// This checker should be enabled regardless of how language options are set.
bool ento::shouldRegisterHTMChecker(const CheckerManager &mgr) { return true; }
