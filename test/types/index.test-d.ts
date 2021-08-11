import { expectAssignable } from "tsd";
import { Strategy, getStrategy, setStrategy, strategies, defaultStrategyName, cache } from "../..";

expectAssignable<Promise<Strategy.Definition>>(getStrategy());
expectAssignable<Promise<Strategy.Definition>>(setStrategy());
expectAssignable<string>(defaultStrategyName);
expectAssignable<Record<string, string>>(strategies);

expectAssignable<cache.Data>(cache.load());
expectAssignable<void>(cache.refresh());
