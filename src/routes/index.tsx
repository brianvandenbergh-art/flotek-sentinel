import { createFileRoute } from "@tanstack/react-router";
import { RedirectToSignIn } from "@/lib/auth/gates";
import { useCurrentUserState } from "@/lib/auth/use-current-user";
import { Console } from "@/components/sentinel/console";

export const Route = createFileRoute("/")({ component: Home });

function Home() {
  const { user, isPending } = useCurrentUserState();
  if (isPending) {
    return (
      <main className="min-h-screen bg-bg">
        <div className="mx-auto max-w-6xl px-4 py-8">
          <div className="h-10 w-40 animate-pulse rounded-xl bg-plum-soft" />
          <div className="mt-6 grid gap-3 sm:grid-cols-4">
            {Array.from({ length: 4 }).map((_, index) => (
              <div key={index} className="h-24 animate-pulse rounded-3xl bg-white" />
            ))}
          </div>
        </div>
      </main>
    );
  }
  if (!user) return <RedirectToSignIn />;
  return <Console />;
}
