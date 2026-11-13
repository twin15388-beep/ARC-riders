#pragma once

// The part of an ESP that is not about the game: reading an offset set, walking a list of actor pointers,
// measuring distance, projecting a world position onto a screen, and serialising the result. Everything
// here is pure (no Win32, no minidump, no renderer) so it can be unit-tested on a fake memory object and
// reused unchanged by the offline dump tool, a live reader, or a test.
//
// Units are Unreal's: positions in centimetres, angles in degrees, and the axes UE uses for a camera
// (forward = +X, right = +Y, up = +Z with roll left at zero, which is what a PlayerCameraManager gives).

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace arc {

struct FVector {
    double x{};
    double y{};
    double z{};
};

struct FRotator {
    double pitch{};
    double yaw{};
    double roll{};  // ignored: the camera cache stores it but no overlay uses it
};

// One definition of "this float triple could be a coordinate in this game", shared by the dump scanner and
// the exporter. A denormal or an infinite value is what a pointer's half reads as, and it has to be
// rejected here rather than at every call site - measured on a real dump, where the sweep's winning
// offset produced (-nan, -nan, -nan) rows because only the magnitude band was checked.
[[nodiscard]] bool IsPlausiblePosition(const FVector& value, double limit = 5.0e6);

// The scanner's stricter rule: every axis has to carry a real coordinate, because a zero axis makes the
// offset ambiguous by one float and lets a neighbouring field win the vote.
[[nodiscard]] bool IsPositionCandidate(const FVector& value, double limit = 5.0e6);

// Distance in metres, which is what an overlay prints.
[[nodiscard]] double DistanceMetres(const FVector& from, const FVector& to);

// Camera basis vectors for a rotation, as rows: forward, right, up.
void CameraBasis(const FRotator& rotation, FVector* forward, FVector* right, FVector* up);

// World to screen. Returns false for anything behind the camera or within `near_cm` of the near plane, so
// a caller never draws a box that has wrapped around from the opposite side of the view. fov_degrees is
// the horizontal field of view (Unreal's convention) and the vertical is derived from the aspect ratio.
struct Viewport {
    FVector eye{};
    FRotator rotation{};
    double fov_degrees{90.0};
    std::uint32_t width{1920};
    std::uint32_t height{1080};
    double near_cm{10.0};

    [[nodiscard]] double VerticalFovDegrees() const;
};

[[nodiscard]] bool WorldToScreen(const FVector& world, const Viewport& view, double* out_x, double* out_y,
    double* out_depth_cm);

// Half height, in pixels, of a sphere of `radius_cm` at `depth_cm`: what turns a position into a box that
// grows when the actor is close instead of a fixed sprite.
[[nodiscard]] double ScreenRadiusPixels(double depth_cm, double radius_cm, const Viewport& view);

// Everything the reader needs to know about a build. A wrong value here is a data problem, not a crash:
// unset fields mean "the feature is off" and the exporter says so in its output.
struct EspOffsetSet {
    std::uint64_t global_rva{};
    std::vector<std::uint64_t> chain;  // pointer hops from the global, before the level fields
    std::uint64_t persistent_level_off{};
    std::uint64_t level_actors_off{};
    std::uint64_t level_owning_world_off{};
    std::uint64_t world_va{};          // set to skip the chain: take the level from this object
    std::uint64_t actor_array_data{};  // set when the array was found by a sweep, no chain needed
    std::uint64_t actor_array_num{};
    std::uint64_t root_component_off{};
    std::uint64_t relative_location_off{};
    std::uint64_t camera_manager_off{};
    std::uint64_t camera_cache_off{};
    std::uint64_t camera_position_off{};
    std::uint64_t camera_rotation_off{};
    std::uint64_t camera_fov_off{};
    std::uint64_t pawn_off{};
    std::uint64_t player_state_off{};
    std::uint64_t health_off{};
    std::uint64_t max_health_off{};
    std::uint64_t team_off{};
    std::uint64_t name_off{};
    FVector local_origin{};  // where the local player was, so distance is meaningful
    double view_pitch_degrees{};
    double view_yaw_degrees{};
    std::uint64_t local_controller_va{};  // set it to read the camera out of the same snapshot
    double fov_degrees{90.0};
    std::uint32_t screen_width{1920};
    std::uint32_t screen_height{1080};
    double actor_radius_cm{85.0};

    [[nodiscard]] bool HasActorList() const noexcept {
        return actor_array_data != 0 && actor_array_num != 0;
    }
    [[nodiscard]] bool HasPositions() const noexcept {
        return relative_location_off != 0 && root_component_off != 0;
    }
    [[nodiscard]] Viewport ScreenView() const noexcept;
};

// Reads the `[esp]` section the dump modes write (or a hand-edited one). Unknown keys are kept quiet and
// other sections are ignored, so the same file can hold the ini blocks of several tools.
[[nodiscard]] EspOffsetSet ParseEspConfig(const std::string& text);
[[nodiscard]] EspOffsetSet LoadEspConfig(const std::filesystem::path& path);

// The memory the exporter walks, abstract so the same code runs against a minidump, a live process, or a
// test's std::vector. Returning nullopt means "not readable" and callers must treat it as missing data.
struct IMemory {
    virtual ~IMemory() = default;
    [[nodiscard]] virtual std::optional<std::uint64_t> Qword(std::uint64_t va) const = 0;
    [[nodiscard]] virtual std::optional<double> Double(std::uint64_t va) const = 0;
    [[nodiscard]] virtual std::optional<float> Float(std::uint64_t va) const = 0;
    [[nodiscard]] virtual std::optional<std::uint32_t> Dword(std::uint64_t va) const = 0;
};

struct EspActor {
    std::uint64_t address{};
    FVector position{};
    double distance_m{};
    bool projected{};
    double screen_x{};
    double screen_y{};
    double box_half_height{};
    bool has_health{};
    float health{};
    float max_health{};
    bool has_team{};
    std::uint32_t team{};
};

// Walks the array and computes everything that does not need a name. Rows with an implausible position are
// skipped rather than emitted, so a stale offset shows up as "0 of N actors" and not as garbage boxes.
std::vector<EspActor> ReadActors(const IMemory& memory, const EspOffsetSet& offsets, std::size_t limit);

// Reads the local view from a controller: CameraManager -> CameraCache -> position/rotation/fov. Any step
// that is not configured or not readable leaves `view` untouched and returns false.
[[nodiscard]] bool ReadLocalView(const IMemory& memory, std::uint64_t player_controller,
    const EspOffsetSet& offsets, Viewport* view);

// Aim target choice, on the data alone: the projected row closest to a point, inside a cone in pixels.
// Returns std::nullopt when nothing is aimable, which is what a caller needs in order to do nothing.
struct AimPick {
    std::size_t index{};
    double offset_px{};
    double distance_m{};
};
[[nodiscard]] std::optional<AimPick> SelectAimTarget(const std::vector<EspActor>& rows, double aim_x,
    double aim_y, double max_offset_px);

// Trigger bot condition: a row whose box covers the aim point. Kept separate from projection so the
// "should the shot be released" rule can be tested and reused without a renderer.
[[nodiscard]] bool IsOnAimPoint(const EspActor& row, double aim_x, double aim_y, double slack_px);

// One JSON document with the rows plus the offsets that produced them, so a renderer can be debugged from
// the file alone. `as_js` wraps it as `window.ARC = ...;` which is what the bundled overlay loads over
// file:// where fetch() of a local .json is blocked.
[[nodiscard]] std::string ToJson(const std::vector<EspActor>& rows, const EspOffsetSet& offsets,
    std::size_t total_actors, bool as_js, std::string_view note);

// A ready-made esp-data.js with a dozen actors placed on a circle, projected by the same WorldToScreen the
// exporter uses. It exists so the overlay can be opened and seen to work before any offset is known: if the
// page draws boxes, the reader, the maths and the renderer are fine and only the offsets are missing.
[[nodiscard]] std::string DemoOverlayData();

// The overlay page that consumes ToJson's output. Emitted by the tool rather than kept as a separate asset
// so `arc_tool esp-overlay <out.html>` plus `esp-export ... esp-data.js` in one folder is the whole setup.
[[nodiscard]] std::string OverlayHtml();

}  // namespace arc
