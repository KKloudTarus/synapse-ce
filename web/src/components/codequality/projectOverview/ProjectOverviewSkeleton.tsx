import { Card, Skeleton } from '../../ui'

export function ProjectOverviewSkeleton() {
  return (
    <div className="space-y-6" aria-label="Loading project overview">
      <Card>
        <Skeleton className="h-7 w-64" />
        <Skeleton className="mt-3 h-4 w-80 max-w-full" />
      </Card>
      <div className="flex justify-end">
        <Skeleton className="h-10 w-56" />
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <Card><Skeleton className="h-20 w-full" /></Card>
        <Card><Skeleton className="h-20 w-full" /></Card>
      </div>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        {Array.from({ length: 6 }, (_, index) => (
          <Card key={index}>
            <Skeleton className="h-5 w-40" />
            <Skeleton className="mt-5 h-10 w-24" />
            <Skeleton className="mt-4 h-4 w-full" />
          </Card>
        ))}
      </div>
    </div>
  )
}
